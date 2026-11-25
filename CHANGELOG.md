# Changelog

## 1.2.0

- Added `--hashcat PATH` to print the SCCM Hashcat mode-19850 hash for a
  `.boot.var`/media variables file and exit.
- Validate the ConfigMgr AES-128 media header and reject non-variables files
  with a clear error.

## 1.1.0

- Native `.boot.var` media variables decryption with `--boot-var` and
  `--password`, without Windows CryptoAPI or PXEThief.
- Decrypted `variables.xml` is written to the output directory.
- Built-in MECM media password fallback when `--password` is omitted.

## 1.0.0

- Initial standalone release.
- Single-file Linux/macOS implementation of the PXEThief PFX/policy stage.
- PFX loading, raw/standard RSA client-token signatures, MECM `CCM_POST` policy
  retrieval, CMS EnvelopedData decryption.
- NAA, Task Sequence, and Collection Variable parsing.
- No Windows CryptoAPI, `win32crypt`, or original PXEThief runtime dependency.
- GPL-3.0 license with PXEThief attribution.
