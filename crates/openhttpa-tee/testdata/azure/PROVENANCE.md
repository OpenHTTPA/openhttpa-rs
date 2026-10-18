# Azure TDX test fixtures

| File                 | Origin                                                                                                                                                                                               |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hcl-report-tdx.bin` | Real HCL report captured on an Azure TDX confidential VM, copied verbatim from Microsoft's `az-cvm-vtpm` 0.8.2 crate (`test/hcl-report-tdx.bin`, MIT, https://github.com/kinvolk/azure-cvm-tooling). |

These fixtures are genuine hardware output and are used only to exercise
parsing and paravisor-binding logic. Integrity: `sha256sum -c SHA256SUMS`.
