#!/usr/bin/env python3
"""Assert this cluster's Longhorn backup gate agrees with its Longhorn.

jg-base ships `Kustomization/longhorn-backup` SUSPENDED. It carries a
RecurringJob that writes to `LONGHORN_BACKUP_TARGET`, and this repo un-suspends
it with a patch wherever `longhorn_backup_target` is set.

Three facts have to agree and they come from three different places: the target
(cluster.yaml), the un-suspend patch (flux/cluster/ks.yaml), and whether
Longhorn is installed at all (`deploy_longhorn`, from `replicated_storage` or
`storage_backend`). Nothing forces them to.

`cue vet` cannot close this. It catches the outright contradiction
(`longhorn_backup_target` set together with `replicated_storage: false` --
measured, it reports "conflicting values true and false"), but not the case
that actually happens: `replicated_storage` simply absent. CUE sees an optional
field it may define as `true`, which is not an error, and plugin.py never reads
CUE's unified value anyway -- it reads cluster.yaml. Measured: target set,
`storage_backend: nfs`, `replicated_storage` absent renders
`deploy_longhorn=False` with `longhorn_backup=nfs`, and `cue vet` exits clean.

What that costs if unchecked: the per-user repo suspends `Kustomization/longhorn`,
jg-base's `longhorn-backup` selects ./nfs, and the RecurringJob is applied
against a CRD that no chart ever installed. The Kustomization goes Ready=False
and stays there, and the operator believes there is a nightly backup.

Runs against the RENDERED artifacts, after render-configs, for the same reason
check-backup-recipient.py does: the input someone meant to write and the output
that ships are different things, and only one of them reaches a cluster.

Exit 0 pass, 1 fail, 2 could not measure -- three outcomes, because a check
that cannot see its subject must not read as one that passed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SECRET = Path('kubernetes/components/sops/cluster-secrets.sops.yaml')
CLUSTER_KS = Path('kubernetes/flux/cluster/ks.yaml')

# Schemes longhorn-manager knows how to write to. A typo here does not fail at
# render or at apply -- the BackupTarget CR simply reports available: false,
# which looks the same as a NAS that is merely unreachable.
SCHEMES = ('nfs://', 'cifs://', 's3://', 'azblob://', 'gcs://')

# Values a YAML 1.1 parser reads as something other than a string. The selector
# lands in stringData, and kustomize does not keep the quotes around the
# placeholder it is substituted into (ferry133/jg-base#16).
NOT_A_STRING = {
    '', '~', 'null', 'Null', 'NULL',
    'true', 'True', 'TRUE', 'false', 'False', 'FALSE',
    'yes', 'Yes', 'YES', 'no', 'No', 'NO',
    'on', 'On', 'ON', 'off', 'Off', 'OFF',
}


def value_of(text: str, key: str) -> str | None:
    m = re.search(rf'^\s+{re.escape(key)}:\s*(.*?)\s*$', text, re.M)
    if m is None:
        return None
    return m.group(1).strip().strip('"').strip("'")


def patched(ks_text: str, name: str) -> tuple[bool | None, str | None]:
    """What the per-user ks.yaml patches (suspend, path) to for `name`.

    None for either field means no patch set it. Matching is per `- patch: |-`
    block and anchored on the whole name, so `longhorn` and `longhorn-backup`
    are never confused for each other -- a distinction this check depends on
    entirely.
    """
    suspend = path = None
    for block in ks_text.split('- patch: |-')[1:]:
        head = block.split('- patch: |-')[0]
        if not re.search(rf'^\s+name:\s*{re.escape(name)}\s*$', head, re.M):
            continue
        m = re.search(r'^\s+suspend:\s*(true|false)\s*$', head, re.M)
        if m:
            suspend = m.group(1) == 'true'
        m = re.search(r'^\s+path:\s*(\S+)\s*$', head, re.M)
        if m:
            path = m.group(1)
    return suspend, path


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    secret, cluster_ks = root / SECRET, root / CLUSTER_KS

    missing = [p for p in (secret, cluster_ks) if not p.is_file()]
    if missing:
        for p in missing:
            print(f'COULD NOT MEASURE  {p} does not exist')
        print('\nRun this after `render-configs`. Reporting "could not measure"')
        print('rather than passing: an absent artifact is not a correct one.')
        return 2

    secret_text = secret.read_text()
    target = value_of(secret_text, 'LONGHORN_BACKUP_TARGET')

    if target is None:
        print('COULD NOT MEASURE  LONGHORN_BACKUP_TARGET is not in the rendered')
        print('  secret. This repo\'s templates/ predate ferry133/jg-base#7. A')
        print('  per-user repo carries its own copy of templates/, and')
        print('  `task configure` exits 0 either way, so this is exactly the')
        print('  state that reads like a pass. Sync templates/ first.')
        return 2

    ks_text = cluster_ks.read_text()
    b_suspend, b_path = patched(ks_text, 'longhorn-backup')
    l_suspend, _ = patched(ks_text, 'longhorn')

    has_target = bool(target)
    want = 'enabled' if has_target else 'disabled'
    position = b_path.rsplit('/', 1)[-1] if b_path else None
    # longhorn itself ships active, so no patch means on.
    longhorn_on = l_suspend is not True

    print(f'LONGHORN_BACKUP_TARGET = {target!r}')
    print(f'longhorn-backup patch  = suspend={b_suspend}, path={b_path}')
    print(f'  wanted position      = {want}')
    print(f'longhorn               = {"active" if longhorn_on else "suspended"}')
    print()

    if b_path is None and b_suspend is None:
        print('COULD NOT MEASURE  nothing in flux/cluster/ks.yaml patches')
        print('  Kustomization/longhorn-backup. This repo\'s templates/ predate')
        print('  ferry133/jg-base#29, which made that patch unconditional.')
        print()
        print('  Whether it matters depends on history this check cannot see:')
        print('  with no patch the Kustomization keeps jg-base\'s suspended')
        print('  default, which is right for a cluster that never turned')
        print('  backups on and WRONG for one that did -- suspend does not')
        print('  remove the RecurringJob it already created. Sync templates/')
        print('  from jg-cluster-template, then re-run.')
        return 2

    failed = []

    if b_suspend is not False:
        failed.append(
            f'the patch leaves suspend={b_suspend}. Off must be an empty path '
            'on a Kustomization that still reconciles, never a suspend: '
            'suspending strands the RecurringJob in longhorn-system and '
            'silences the only object that would report it, at the same moment')
    if position != want:
        failed.append(
            f'patched path selects {position!r} but the target says {want!r} '
            + ('(a target is set, so the RecurringJob must actually be applied)'
               if has_target else
               '(no target, so the path must be the empty directory or Flux '
               'never prunes what a previous render applied)'))
    if has_target and not target.startswith(SCHEMES):
        failed.append(
            f'LONGHORN_BACKUP_TARGET {target!r} has no scheme Longhorn '
            f'accepts ({", ".join(SCHEMES)}); the BackupTarget CR reports '
            'available: false, which looks the same as an unreachable NAS')
    if has_target and not longhorn_on:
        failed.append(
            'a backup target is set but this cluster suspends '
            'Kustomization/longhorn, so the RecurringJob is applied against a '
            'CRD no chart installs. Set replicated_storage: true (or '
            'storage_backend: "replicated") if Longhorn is wanted here, or '
            'drop longhorn_backup_target if it is not')

    if failed:
        for f in failed:
            print(f'FAIL  {f}')
        return 1

    if not has_target:
        print('ok - no Longhorn backup configured, and the switch is in the')
        print('     empty position rather than suspended, so anything a')
        print('     previous render applied is pruned rather than stranded.')
    else:
        print('ok - target set, switch in the enabled position, Longhorn installed.')
        print()
        print('     NOT checked here, and not checkable from a template repo:')
        print('     whether the export accepts writes from longhorn')
        print('     instance-manager, and whether a backup has ever been')
        print('     restored. A backup target that has never restored is a')
        print('     hypothesis.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
