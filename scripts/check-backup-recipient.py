#!/usr/bin/env python3
"""Assert the rendered backup recipient is THIS cluster's own public key.

Off-site backups are encrypted to the cluster's age public key before upload,
and `backup_age_recipient` is derived rather than declared. Both ways of
deriving it wrong are silent at render time:

  empty      the CronJob refuses to upload ("FATAL: BACKUP_AGE_RECIPIENT is
             empty; refusing to upload unencrypted data") every night for the
             life of the appliance. Refusing is correct — uploading readable
             data to someone else's object store is worse — but nothing says
             so at `task configure` time, which still exits 0.

  wrong key  worse. Uploads succeed, the log says `uploaded`, the bucket fills
             up, and every archive is unreadable with the age.key that travels
             with this cluster. Discovered on the day of the restore, which is
             the day it cannot be fixed.

This is why it compares against `age.key` rather than against `.sops.yaml`:
a positive control has to share the property under test, and what a restore
actually needs is the key the cluster hands over at delivery.

Runs against the RENDERED secret, between render and encrypt, so it measures
the artifact that ships rather than the input someone meant to write.

Exit 0 pass, 1 fail, 2 could not measure — three outcomes, because a check that
cannot see its subject must not read as one that passed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SECRET = Path('kubernetes/components/sops/cluster-secrets.sops.yaml')


def value_of(text: str, key: str) -> str | None:
    match = re.search(rf'^\s+{key}:\s*(.*?)\s*$', text, re.M)
    if match is None:
        return None
    return match.group(1).strip().strip('"').strip("'")


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    secret = root / SECRET
    if not secret.is_file():
        print(f'CANNOT MEASURE: {SECRET} not rendered yet', file=sys.stderr)
        return 2
    text = secret.read_text()

    bucket = value_of(text, 'BACKUP_R2_BUCKET')
    recipient = value_of(text, 'BACKUP_AGE_RECIPIENT')
    if bucket is None or recipient is None:
        print('CANNOT MEASURE: BACKUP_R2_BUCKET or BACKUP_AGE_RECIPIENT is not'
              ' in the rendered secret at all', file=sys.stderr)
        return 2
    if bucket.startswith('ENC[') or recipient.startswith('ENC['):
        print('CANNOT MEASURE: the rendered secret is already encrypted; this'
              ' check has to run between render-configs and encrypt-secrets',
              file=sys.stderr)
        return 2

    if not bucket:
        print('off-site backup is not configured on this cluster'
              ' (BACKUP_R2_BUCKET is empty), so an empty recipient is not a'
              ' defect here — nothing is uploaded either way')
        return 0

    expected = ''
    for source, pattern in ((root / 'age.key',
                             r'#\s*public key:\s*(age1[a-z0-9]+)'),
                            (root / '.sops.yaml',
                             r'age:\s*["\']?(age1[a-z0-9]+)')):
        if not source.is_file():
            continue
        match = re.search(pattern, source.read_text())
        if match:
            expected = match.group(1)
            break
    if not expected:
        print('CANNOT MEASURE: no age public key found in age.key or'
              ' .sops.yaml, so there is nothing to compare against',
              file=sys.stderr)
        return 2

    if not recipient:
        print('FAIL: BACKUP_AGE_RECIPIENT rendered empty while'
              f' BACKUP_R2_BUCKET is "{bucket}".\n'
              '      The nightly backup will refuse to upload — every night,'
              ' silently, until someone reads the Job log.\n'
              f'      Expected this cluster\'s own key: {expected}',
              file=sys.stderr)
        return 1

    if recipient != expected:
        print('FAIL: backups would be encrypted to a key this cluster does'
              ' not hold.\n'
              f'      rendered: {recipient}\n'
              f'      age.key : {expected}\n'
              '      Uploads would succeed and every archive would be'
              ' unreadable at restore time.', file=sys.stderr)
        return 1

    print(f'backup recipient is this cluster\'s own key: {expected}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
