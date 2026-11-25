# pxecred

Cross-platform SCCM/MECM PXE media and policy credential extractor for Linux and macOS.

`pxecred` is a single-file, standalone alternative to the Windows-only
`win32crypt` stage of [PXEThief](https://github.com/MWR-CyberSec/PXEThief).
It decrypts a saved PXE media variables file (`.boot.var`) with its media
password, extracts the media PFX, retrieves the Network Access Account, Task
Sequence, and Collection Variable policies from a Configuration Manager
Management Point, and decrypts them without Windows CryptoAPI.

> **Authorized use only.** This tool retrieves credentials and is intended for
> penetration tests, red-team labs, and systems you own or have explicit written
> permission to assess. You are responsible for complying with applicable law.

## Why

PXEThief extracts the OSD media variables and PFX, but its policy retrieval and
credential parsers depend on `win32crypt` and therefore run only on Windows.
`pxecred` reimplements that stage with portable Python:

- `.boot.var` media-variable decryption with the PXE media password
- PFX loading via `cryptography`
- MECM client token signatures via RSA PKCS#1 v1.5
- `CCM_POST` policy retrieval
- CMS/PKCS#7 enveloped response decryption via `asn1crypto` + AES-CBC
- The same SCCM credential deobfuscation and Task Sequence parsing workflow

## Requirements

- Python 3.9+
- Linux or macOS
- Network access to the MECM Management Point
- An encrypted PXE media variables file (`.boot.var`) and its password, or an
  already-decrypted `variables.xml`

The tool does **not** perform DHCP/TFTP acquisition itself. Download the
`.boot.var`/BCD from the distribution point with TFTP or another PXE extraction
method, then pass the `.boot.var` to `--boot-var`. If you already have a
decrypted `variables.xml`, use `--variables` instead. The media PFX is extracted
from `_SMSTSMediaPFX` automatically unless `--pfx` is supplied.

## Install

```bash
git clone <your-fork-url> pxecred
cd pxecred
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Or install the command with pipx:

```bash
pipx install .
pxecred --help
```

The tool is a single file; running `python pxecred.py` directly also works once
the dependencies are installed.

## Quick start

Decrypt the media variables and retrieve policies in one command:

```bash
python pxecred.py \
  --boot-var media.boot.var \
  --password hello \
  --mp http://192.168.0.41
```

If you already have a decrypted `variables.xml` and PFX:

```bash
python pxecred.py \
  --variables variables.xml \
  --pfx P01_media_SMSTSMediaPFX.pfx \
  --mp http://192.168.0.41
```

If the PFX password is the standard MECM media-GUID prefix, it is derived from
`_SMSMediaGuid` automatically. Override it with `--pfx-password`.

## Generate a Hashcat hash

Print the SCCM Hashcat mode-19850 hash for an encrypted media variables file:

```bash
python pxecred.py --hashcat media.boot.var
```

Example:

```text
$sccm$aes128$0000edec1400000010340000203400000e66000000000000f4aa05d12d6facd1856ed8f2fe6cfa41
```

The hash is derived from the first 40 bytes of the media variables file. The
downloaded `.boot.bcd` is a Windows registry hive (it starts with `regf`), not
an encrypted media variables file, so it has no `$sccm$aes128$` hash. Use the
`.boot.var` or another media variables file.

Hashcat mode 19850 is not built into stock Hashcat; use the MWR CyberSec
[ConfigMgr module](https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module)
or a binary that includes it.

Outputs are written to `pxecred-output/` by default:

- `policy_assignments.xml` — policy assignment document
- `NAAConfig.xml` — decrypted NAA policy
- `TaskSequence.xml` — decrypted Task Sequence policy
- `TaskSequence_<name>.xml` — decrypted task sequence
- `TaskSequence_policy_<name>.xml` — original policy XML

Example output:

```text
[!] NAA Username: 'LAB\sccm-naa'
[!] NAA Password: '<redacted>'
[+] Task Sequence: Install_win10_OS_image
In TS Step "Apply Windows Settings":
  OSDLocalAdminPassword - <redacted>
In TS Step "Apply Network Settings":
  OSDJoinAccount - LAB\sccm-naa
  OSDJoinPassword - <redacted>
```

## Options

| Option | Description |
|---|---|
| `--boot-var PATH` | Encrypted PXE media variables file (`.boot.var`) |
| `--hashcat PATH` | Print the SCCM Hashcat mode-19850 hash for a media variables file and exit |
| `--password VALUE` | Password for `--boot-var` (default: built-in MECM media password) |
| `--variables PATH` | Already-decrypted PXE media variables XML |
| `--pfx PATH` | Media PFX; if omitted, extracted from `_SMSTSMediaPFX` |
| `--pfx-password VALUE` | PFX password (default: first 31 chars of `_SMSMediaGuid`) |
| `--mp URL` | Management Point base URL; default from `SMSTSMP`/`SMSTSLocationMPs` |
| `--output DIR` | Output directory (default `pxecred-output`) |
| `--sig-mode MODE` | `auto`, `raw-little`, `raw-big`, `std-little`, `std-big` |
| `--hash ALG` | `sha256` (default) or `sha1` |
| `--timeout SECONDS` | HTTP timeout (default 30) |
| `--version` | Print version |
| `-h, --help` | Help |

`auto` tries `raw-little`, `std-little`, `raw-big`, and `std-big` in order.
MECM commonly accepts `raw-little` with SHA-256, which is what modern site
servers use for the client token signatures.

## How it works

1. If `--boot-var` is used, decrypt the media variables with the PXE password
   (AES-128-CBC, CryptDeriveKey SHA-1 key derivation, 24-byte header and 8-byte
   trailer removed); otherwise read `variables.xml`.
2. Derive the media GUID and load the media PFX with its derived password.
3. Fetch `x86UnknownMachineGUID` and the site code from
   `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
4. Sign the client ID, timestamp, and client token with the PFX private key.
5. POST a `CCM_POST` policy request to `/ccm_system/request`.
6. Parse the returned policy assignment URLs and fetch NAA, Task Sequence, and
   Collection Settings policies.
7. Decrypt CMS EnvelopedData responses with the PFX private key.
8. Deobfuscate NAA/Collection Variable secrets and parse Task Sequence steps.

## Troubleshooting

- **`Failed to decrypt media variables; check the password`** — the
  `--password` is wrong, or the file is not a PXE media variables `.boot.var`.
  For unprotected media, omit `--password` to use the built-in MECM password.
- **`MPKEYINFORMATIONMEDIA` fails / wrong host** — pass `--mp` explicitly,
  usually `http://<MECM-IP>`. A hostname from `SMSTSMP` may not resolve on your
  attack host.
- **Policy request returns 401/500** — try `--sig-mode std-little`, then the
  other modes; try `--hash sha1`; verify the system clock is correct.
- **CMS decrypt fails** — verify the PFX and `--pfx-password`; the PFX must be
  the media PFX whose certificate the site encrypted to.
- **No NAA/TS policies** — the site may not have them assigned to Unknown
  Computers; the policy assignment document is still written for inspection.
- **HTTPS** — the tool follows the URL you provide. For HTTPS endpoints with a
  private CA, provide a reachable MP URL or use an HTTP management point when
  testing in an isolated lab.

## Credits and license

`pxecred` is based on the PXEThief workflow and parser behavior by Christopher
Panayi / [MWR CyberSec](https://github.com/MWR-CyberSec/PXEThief). The media
variables decryption, Windows CryptoAPI stage, and certificate/policy handling
are reimplemented with portable Python. Because it derives from PXEThief, it is
distributed under the **GNU General Public License v3.0**; see `LICENSE`.

No original PXEThief code is imported at runtime. `pxecred.py` is standalone.
