# pxecred

Cross-platform SCCM/MECM PXE policy credential extractor for Linux and macOS.

`pxecred` is a single-file, standalone alternative to the Windows-only
`win32crypt` stage of [PXEThief](https://github.com/MWR-CyberSec/PXEThief).
It consumes a PXE media variables XML file and its media PFX, retrieves the
Network Access Account, Task Sequence, and Collection Variable policies from a
Configuration Manager Management Point, and decrypts them without Windows
CryptoAPI.

> **Authorized use only.** This tool retrieves credentials and is intended for
> penetration tests, red-team labs, and systems you own or have explicit written
> permission to assess. You are responsible for complying with applicable law.

## Why

PXEThief extracts the OSD media variables and PFX, but its policy retrieval and
credential parsers depend on `win32crypt` and therefore run only on Windows.
`pxecred` reimplements that stage with portable Python:

- PFX loading via `cryptography`
- MECM client token signatures via RSA PKCS#1 v1.5
- `CCM_POST` policy retrieval
- CMS/PKCS#7 enveloped response decryption via `asn1crypto` + AES-CBC
- The same SCCM credential deobfuscation and Task Sequence parsing workflow

## Requirements

- Python 3.9+
- Linux or macOS
- Network access to the MECM Management Point
- A PXE media `variables.xml` and its extracted media PFX

The tool does **not** perform PXE/DHCP/TFTP extraction itself. Obtain the media
variables and PFX with PXEThief (mode 1/2/3 on a supported platform) or an
equivalent extraction method. `pxecred` can extract the PFX from
`_SMSTSMediaPFX` in the variables XML if `--pfx` is omitted.

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

```bash
python pxecred.py \
  --variables variables.xml \
  --pfx P01_media_SMSTSMediaPFX.pfx \
  --mp http://192.168.0.41
```

If the PFX password is the standard MECM media-GUID prefix, it is derived from
`_SMSMediaGuid` automatically. Override it with `--pfx-password`.

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
| `--variables PATH` | PXE media variables XML (default `variables.xml`) |
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

1. Read `variables.xml` and derive the media GUID.
2. Load the media PFX with the derived password.
3. Fetch `x86UnknownMachineGUID` and the site code from
   `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
4. Sign the client ID, timestamp, and client token with the PFX private key.
5. POST a `CCM_POST` policy request to `/ccm_system/request`.
6. Parse the returned policy assignment URLs and fetch NAA, Task Sequence, and
   Collection Settings policies.
7. Decrypt CMS EnvelopedData responses with the PFX private key.
8. Deobfuscate NAA/Collection Variable secrets and parse Task Sequence steps.

## Troubleshooting

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
Panayi / [MWR CyberSec](https://github.com/MWR-CyberSec/PXEThief). The Windows
CryptoAPI stage is reimplemented with portable Python. Because it derives from
PXEThief, it is distributed under the **GNU General Public License v3.0**; see
`LICENSE`.

No original PXEThief code is imported at runtime. `pxecred.py` is standalone.
