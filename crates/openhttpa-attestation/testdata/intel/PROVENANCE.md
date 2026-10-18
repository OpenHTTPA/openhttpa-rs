# Intel TDX test fixtures

| File                                                       | Origin                                                                                                                                                                                                             |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `../../certs/intel_sgx_root_ca.der`                        | Intel SGX Provisioning Certification Root CA, byte-identical to https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer (downloaded 2026-10-18, SHA-256 `44a0196b…74d3`).   |
| `tdx_quote`, `tdx_quote_collateral.json`                   | Real Intel-signed TDX v4 quote and the Intel PCS collateral fetched for it, copied verbatim from `dcap-qvl` 0.7.0 `sample/` (MIT, https://github.com/Phala-Network/dcap-qvl). TCB status `UpToDate` at 2025-06-21. |
| `tdx_quote_outdated`, `tdx_quote_outdated_collateral.json` | Real Intel-signed TDX quote whose platform TCB is out of date under its collateral; same source.                                                                                                                   |

These are genuine Intel signatures. They are not from Azure and are used only
to exercise DCAP chain/CRL/TCB/measurement logic with a fixed clock.
Integrity: `sha256sum -c testdata/intel/SHA256SUMS` from `crates/openhttpa-attestation`.
