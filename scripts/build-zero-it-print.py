#!/usr/bin/env python3
"""Produce the printable copy of README-zero-IT.md, and prove it is current.

The customer reads this on paper, because when they read it the network is not
up yet — a URL is not an entry point at that moment. CLAUDE.md therefore
requires the paper and the Markdown to come from one source, never transcribed
by hand.

Two failure modes matter, and they are different:

  wrong content   a hand-made copy drifts from the file. Solved by generating.
  wrong VERSION   the file changed and a box shipped with last month's sheet.
                  Nothing about a printed page says which revision it is, and
                  an outdated sheet reads exactly like a current one.

So every page carries a stamp derived from the source bytes, and the built file
is named after it. `--check` compares the newest build against the source and
distinguishes three outcomes, never two: current / stale / nothing built. The
third is the one a two-state check silently reports as fine.

Markdown handling is deliberately strict. Every line must match a known rule;
anything else aborts. A renderer that quietly drops what it does not understand
would produce a page that looks complete, which is the one outcome nobody can
see on paper.

Usage:
  build-zero-it-print.py            build dist/zero-it/<name>-<stamp>.pdf
  build-zero-it-print.py --check    verify a current build exists
  build-zero-it-print.py --html     stop at HTML (no Chrome needed)
"""

from __future__ import annotations

import argparse
import hashlib
import html
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

QR_RE = re.compile(r"^\[QR:\s*(\S+)\s*\]$")

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "README-zero-IT.md"
OUTDIR = ROOT / "dist" / "zero-it"

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome",
    "chromium",
    "chromium-browser",
]


def stamp_of(text: str) -> str:
    """Short, human-readable, derived from the bytes a reader would compare."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


# --------------------------------------------------------------------------
# Markdown subset. Strict on purpose: see the module docstring.
# --------------------------------------------------------------------------

def inline(text: str) -> str:
    """**bold** and `code`. Everything else is literal text."""
    out, pos = [], 0
    for m in re.finditer(r"\*\*(.+?)\*\*|`(.+?)`", text):
        out.append(html.escape(text[pos:m.start()]))
        if m.group(1) is not None:
            out.append(f"<strong>{html.escape(m.group(1))}</strong>")
        else:
            out.append(f"<code>{html.escape(m.group(2))}</code>")
        pos = m.end()
    out.append(html.escape(text[pos:]))
    return "".join(out)


def render_body(md: str) -> str:
    out: list[str] = []
    list_open = False
    quote: list[str] = []

    def close_list():
        nonlocal list_open
        if list_open:
            out.append("</ul>")
            list_open = False

    def close_quote():
        if quote:
            out.append(f'<blockquote>{" ".join(quote)}</blockquote>')
            quote.clear()

    for lineno, raw in enumerate(md.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            close_list()
            close_quote()
            continue
        if line.startswith("> "):
            close_list()
            quote.append(inline(line[2:].strip()))
            continue
        close_quote()
        if m := QR_RE.match(line):
            close_list()
            out.append(qr_block(m.group(1)))
        elif re.fullmatch(r"-{3,}", line):
            close_list()
            out.append('<hr class="rule">')
        elif m := re.match(r"^(#{1,4})\s+(.*)$", line):
            close_list()
            level = len(m.group(1))
            out.append(f"<h{level}>{inline(m.group(2).strip())}</h{level}>")
        elif m := re.match(r"^[-*]\s+(.*)$", line):
            if not list_open:
                out.append("<ul>")
                list_open = True
            out.append(f"<li>{inline(m.group(1).strip())}</li>")
        elif re.match(r"^\S", line) or line.startswith("  "):
            close_list()
            out.append(f"<p>{inline(line.strip())}</p>")
        else:
            raise SystemExit(
                f"{SOURCE.name}:{lineno}: unrecognised markdown, refusing to "
                f"render a page that would silently omit it:\n  {raw!r}")
    close_list()
    close_quote()
    return "\n".join(out)


def qr_block(url: str) -> str:
    """Render the QR inline, or abort.

    The URL lives in the Markdown so the paper and the code cannot disagree —
    a QR produced from a value kept somewhere else is a second artifact with its
    own version, which is the drift this whole script exists to prevent.

    A missing encoder must stop the build. A sheet printed without its QR looks
    finished, and the customer discovers the gap at the moment they need help.
    """
    segno = shutil.which("segno")
    if not segno:
        raise SystemExit(
            "segno not found, refusing to print a sheet with the QR missing "
            "(it would look complete). It is pinned in .mise.toml — run "
            "`mise install`, or `mise exec -- task print-zero-it`.")
    # segno picks its format from the output file's extension, so it needs a
    # real .svg path — "-" is read as an extension, not as stdout.
    #
    # --no-xmldecl because the SVG is inlined into an HTML document, where an
    # XML declaration is invalid; --no-size so the CSS decides the printed
    # dimensions rather than a pixel count.
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "qr.svg"
        subprocess.run(
            [segno, f"--output={out}", "--no-xmldecl", "--no-size",
             "--scale=5", "--border=2", "--error=M", url],
            check=True, capture_output=True, text=True)
        svg = out.read_text(encoding="utf-8").strip()
    if "<svg" not in svg:
        raise SystemExit(f"segno returned no SVG for {url!r}")
    # The caption is what makes the QR an aid rather than the entry point
    # (task 4.7). It has to be on the paper, not only in the design notes.
    return (f'<div class="qr">{svg}'
            f'<div class="qr-note">用手機相機對準就可以加入 LINE 好友<br>'
            f'掃不出來也沒關係，直接打上面的電話一樣找得到我們</div></div>')


# Print-first stylesheet: A4, generous leading, and a stamp repeated on every
# sheet so a page separated from the rest still says which revision it is.
CSS = """
@page { size: A4; margin: 18mm 16mm 22mm 16mm; }
* { box-sizing: border-box; }
body {
  font-family: "PingFang TC", "Noto Sans CJK TC", "Hiragino Sans CNS",
               "Microsoft JhengHei", sans-serif;
  font-size: 12.5pt; line-height: 1.85; color: #111; margin: 0;
  -webkit-font-smoothing: antialiased;
}
h1 { font-size: 24pt; margin: 0 0 14pt; letter-spacing: .5pt; }
h2 { font-size: 16pt; margin: 22pt 0 8pt; page-break-after: avoid; }
h3 { font-size: 13.5pt; margin: 16pt 0 6pt; page-break-after: avoid; }
p, li { margin: 0 0 8pt; }
ul { margin: 0 0 10pt; padding-left: 1.4em; }
li { padding-left: .2em; }
strong { font-weight: 700; }
blockquote {
  margin: 10pt 0; padding: 9pt 12pt; border-left: 3pt solid #333;
  background: #f4f4f4; page-break-inside: avoid;
}
hr.rule { border: 0; border-top: .6pt solid #bbb; margin: 16pt 0; }
.qr { margin: 14pt 0; page-break-inside: avoid; text-align: center; }
.qr svg { width: 38mm; height: 38mm; }
.qr-note { font-size: 10.5pt; line-height: 1.6; color: #333; margin-top: 5pt; }
h2, h3, blockquote, ul { page-break-inside: avoid; }
.stamp {
  position: fixed; bottom: 8mm; left: 16mm; right: 16mm;
  font-size: 8pt; color: #666; letter-spacing: .3pt;
  border-top: .4pt solid #ddd; padding-top: 3pt;
}
"""

PAGE = """<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>{title}</title><style>{css}</style></head>
<body>
{body}
<div class="stamp">版本 {stamp}　·　此頁由 {source} 產生，請勿手抄或改寫</div>
</body></html>
"""


def find_chrome() -> str | None:
    for c in CHROME_CANDIDATES:
        if Path(c).exists():
            return c
        if found := shutil.which(c):
            return found
    return None


def build(html_only: bool) -> int:
    md = SOURCE.read_text(encoding="utf-8")
    stamp = stamp_of(md)
    OUTDIR.mkdir(parents=True, exist_ok=True)

    page = PAGE.format(title=SOURCE.stem, css=CSS, body=render_body(md),
                       stamp=stamp, source=SOURCE.name)
    html_path = OUTDIR / f"{SOURCE.stem}-{stamp}.html"
    html_path.write_text(page, encoding="utf-8")
    print(f"html   {html_path.relative_to(ROOT)}")

    if html_only:
        return 0

    chrome = find_chrome()
    if not chrome:
        print("\nNo Chrome or Chromium found, so no PDF was produced.")
        print("The HTML above is complete — open it and print to PDF by hand,")
        print("or re-run with --html to acknowledge that as the intended output.")
        print("Tried: " + ", ".join(CHROME_CANDIDATES))
        return 1

    pdf_path = OUTDIR / f"{SOURCE.stem}-{stamp}.pdf"
    subprocess.run([
        chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_path}", html_path.as_uri(),
    ], check=True, capture_output=True)

    if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
        print(f"Chrome exited cleanly but produced no usable PDF at {pdf_path}")
        return 1
    print(f"pdf    {pdf_path.relative_to(ROOT)}  ({pdf_path.stat().st_size // 1024} KB)")
    print(f"stamp  {stamp}   ← printed on every page; compare before printing")
    return 0


def check() -> int:
    md = SOURCE.read_text(encoding="utf-8")
    stamp = stamp_of(md)
    built = sorted(OUTDIR.glob(f"{SOURCE.stem}-*.pdf")) if OUTDIR.is_dir() else []

    # Three outcomes, never two. "Nothing built" is the one a match/mismatch
    # test reports as fine by omission.
    if not built:
        print(f"NOT BUILT  no {SOURCE.stem}-*.pdf under {OUTDIR.relative_to(ROOT)}")
        print("           This is not 'up to date'. There is no paper copy to ship.")
        return 1
    current = OUTDIR / f"{SOURCE.stem}-{stamp}.pdf"
    if current.is_file():
        stale = [p.name for p in built if p != current]
        print(f"ok — {current.name} matches {SOURCE.name} (stamp {stamp})")
        if stale:
            print(f"     {len(stale)} older build(s) still present: {', '.join(stale)}")
            print("     Every page carries its own stamp, so an old sheet is")
            print("     identifiable — but do not print from these.")
        return 0
    print(f"STALE      {SOURCE.name} now stamps {stamp}, and no build carries it.")
    print(f"           Newest build: {built[-1].name}")
    print("           A box shipped with that sheet would carry an old revision,")
    print("           and nothing on the paper would look wrong.")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="verify a build exists and matches the source")
    ap.add_argument("--html", action="store_true",
                    help="stop at HTML; do not invoke Chrome")
    args = ap.parse_args()
    if not SOURCE.is_file():
        raise SystemExit(f"{SOURCE} not found")
    return check() if args.check else build(args.html)


if __name__ == "__main__":
    raise SystemExit(main())
