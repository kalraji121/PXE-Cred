# Changelog

## 1.0.0

- Initial standalone release.
- Single-file Linux/macOS implementation of the PXEThief PFX/policy stage.
- PFX loading, raw/standard RSA client-token signatures, MECM `CCM_POST` policy
  retrieval, CMS EnvelopedData decryption.
- NAA, Task Sequence, and Collection Variable parsing.
- No Windows CryptoAPI, `win32crypt`, or original PXEThief runtime dependency.
- GPL-3.0 license with PXEThief attribution.
