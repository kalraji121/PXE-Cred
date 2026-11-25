# Security policy

## Intended use

`pxecred` retrieves credentials from SCCM/MECM PXE media and policies. It is
intended only for authorized penetration tests, red-team labs, and systems you
own or have explicit written permission to assess.

Do not use it against third-party systems without authorization.

## Sensitive data

`pxecred` writes decrypted policies, raw HTTP bodies, and extracted credentials.
Treat the output directory and any `variables.xml`/PFX input as secrets. They are
excluded by `.gitignore` by default, but you are responsible for storage and
retention outside the repository.

## Reporting a vulnerability

If you find a security issue in `pxecred` itself, open a private security
advisory or contact the maintainer rather than filing a public issue with exploit
details. This policy does not cover vulnerabilities in SCCM/MECM or in third-party
targets.

## No warranty

The software is provided under the GNU General Public License v3.0, without
warranty. See `LICENSE`.
