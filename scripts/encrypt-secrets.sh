#!/usr/bin/env bash
# Encrypt rendered SOPS files, keeping the committed ciphertext when the
# plaintext has not changed.
#
# Why this exists
# ---------------
# `task configure` re-renders every template on every run (makejinja `force =
# true`), which overwrites each *.sops.* file with fresh plaintext. The old
# encrypt step then saw `encrypted: false` -- correctly -- and re-encrypted.
#
# SOPS derives a new data key and new IVs on every encryption, so identical
# plaintext produces entirely different ciphertext. Measured, not assumed:
# encrypting two byte-identical files with the same recipient yields different
# `ENC[AES256_GCM,data:...,iv:...]` for every value.
#
# The result was ~162 lines of secret diff on every no-op `task configure`.
# That is not cosmetic. Deciding such a diff is safe means decrypting both
# sides and comparing plaintext, and nobody does that on the twentieth run --
# so the diff stops being read, and the run where it *is* a real secret change
# looks exactly like the nineteen before it. A signal that fires every time is
# a signal that has been muted.
#
# So: encrypt only what actually changed. If HEAD already holds ciphertext that
# decrypts to exactly what we just rendered, put HEAD's bytes back.
#
# Fail-safe direction: every uncertainty (not tracked, not in HEAD, HEAD not
# encrypted, decryption fails, bytes differ) falls through to a normal
# encryption. The committed copy is only restored on a proven byte-identical
# match, so this can lose churn and cannot lose a change.

set -euo pipefail

command -v sops >/dev/null || { echo "sops not found" >&2; exit 1; }
command -v jq   >/dev/null || { echo "jq not found" >&2; exit 1; }
command -v yq   >/dev/null || { echo "yq not found" >&2; exit 1; }

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || true)

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

kept=0
encrypted=0

is_encrypted() {
    # `sops filestatus` needs the extension to pick a parser, so the temp copy
    # must keep it. Anything that is not a clean "true" counts as not encrypted.
    [ "$(sops filestatus "$1" 2>/dev/null | jq -r '.encrypted' 2>/dev/null)" = "true" ]
}

# awk, not `sed '1{/^---$/d}'`: BSD sed rejects that form with "extra
# characters at the end of d command", and it fails inside a pipeline whose
# stderr the caller discards -- so the comparison silently produced nothing and
# every file fell through to re-encryption. The first version of this fix was
# exactly that, and only a real render caught it.
strip_doc_marker() {
    awk 'NR==1 && $0=="---"{next}{print}'
}

# Directories in, files found here. Taking a pre-built list as arguments meant
# the caller had to interpolate newline-separated paths into a command line,
# where the shell reads each newline as a command separator.
dirs=()
for d in "$@"; do
    [ -d "$d" ] && dirs+=("$d")
done
[ ${#dirs[@]} -gt 0 ] || { echo "sops: no secret directories present, nothing to do"; exit 0; }

while IFS= read -r -d '' file; do
    if is_encrypted "$file"; then
        continue
    fi

    # Freshly rendered plaintext. Ask git whether it already holds a version
    # whose plaintext is the same.
    restored=false
    if [ -n "$repo_root" ]; then
        rel=$(git -C "$repo_root" ls-files --full-name --error-unmatch "$file" 2>/dev/null || true)
        if [ -n "$rel" ]; then
            head_copy="$tmpdir/head-$(basename "$file")"
            if git -C "$repo_root" show "HEAD:$rel" > "$head_copy" 2>/dev/null \
               && [ -s "$head_copy" ] \
               && is_encrypted "$head_copy"; then
                # Compare as parsed YAML, not as bytes. SOPS reserialises on
                # encrypt: `TOKEN: "x"` at two-space indent comes back as
                # `TOKEN: x` at four. Measured — a byte comparison here never
                # matches, so this whole branch would be dead code that reads
                # like a working optimisation. Normalising *both* sides through
                # the same yq makes them equal when the content is equal, and
                # comments survive the round trip so a comment-only edit still
                # counts as a change.
                # `strip_doc_marker` on both sides, and it is load-bearing.
                # makejinja renders these files with a leading `---` document
                # marker; `sops --decrypt` returns the same document without
                # one, and `yq -P` faithfully preserves the difference. Four
                # bytes, present on every render, so every file compared as
                # changed and #7's churn survived its own fix -- measured on
                # jcom 2026-08-18, where sops-age.sops.yaml re-encrypted on a
                # run whose plaintext was byte-identical.
                #
                # This did not show up in the original tests because those
                # fixtures were hand-written and encrypted with sops, so both
                # sides of the comparison had been through sops. The renderer
                # was never in the loop. The test was right; the inputs were not.
                head_plain="$tmpdir/plain-$(basename "$file")"
                if sops --decrypt "$head_copy" 2>/dev/null | yq -P '.' | strip_doc_marker > "$head_plain" 2>/dev/null \
                   && [ -s "$head_plain" ] \
                   && yq -P '.' "$file" 2>/dev/null | strip_doc_marker | cmp -s - "$head_plain"; then
                    # Same plaintext. Keep the committed ciphertext so the file
                    # does not appear in `git status` at all.
                    cat "$head_copy" > "$file"
                    restored=true
                    kept=$((kept + 1))
                fi
            fi
        fi
    fi

    if [ "$restored" = false ]; then
        sops --encrypt --in-place "$file"
        encrypted=$((encrypted + 1))
        echo "encrypted (content changed): ${file#"$repo_root"/}"
    fi
done < <(find "${dirs[@]}" -type f -name "*.sops.*" -print0 2>/dev/null)

echo "sops: ${encrypted} re-encrypted, ${kept} unchanged (committed ciphertext kept)"
