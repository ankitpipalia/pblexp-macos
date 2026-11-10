# Required resources (not included)

These are proprietary OEM/Qualcomm payloads from the owned RMX1901 firmware.
They are deliberately **not** committed to this public repository. Place them
in this directory, or pass `--resources DIR`.

| File | Size | SHA-256 |
|---|---:|---|
| `oppo710_elf_header.bin` | `0x40` | `8b0783b70f4793cdddbce64d51775ec1b261a65968ef3087bd44aa046360ba4a` |
| `oppo710_program_headers.bin` | `0x4d0` | `fbb4b23984616972b225c48298a9f82d8d39c76b0ca304e066c095be28ead42e` |
| `segment1.bin` | `0x1000` | `da6cffd174d8bac3d56b7b024ff35cca6d393368f7de7a719ea3e0f2bff58b5b` |
| `segment2.bin` | `0x3f0` | `26712a9af552ca20a9594ab0f6eb96427b302388a47f7f8672c6b002fa36aa3a` |
| `segment3.bin` | `0x3a8` | `d68e5c4385f289c59469c0567718a4b127a56321cf3bb722298c58814d312692` |
| `common_zero_segment.bin` | `0xbf8` | `cb9d8ad98a67bce84c7726b113d37ba7b9a48a87431c0ad9422ffbbb85da4e51` (all zero) |

A missing `common_zero_segment.bin` is generated as `0xbf8` zero bytes and
checked against the hash above. The 48-byte Hello710 is hardcoded; no
`hello710.bin` is required or read. The older 24-byte capture with SHA-256
`76a8fe1e9604171f9d749eff16996a586727e4167d945b2a67eaeefda7a90225`
is historical evidence, not a loaded resource.

These hashes record private extraction results; the source binaries are absent
from the public checkout and were not independently reproduced by the review.

The signed programmer (`devprg_710`) is an OEM image; supply it with
`--image`. Do not redistribute proprietary Qualcomm/OPPO binaries.

Custom `--segment1` overrides require a matching explicit `--segment1-hash`
and the expected `0x1000` size. Historical experimental candidates:

| File | SHA-256 |
|---|---|
| `segment1_loader_table.bin` | `f488ee5034c84a14826b2fd6c12899c11137ac75998bcff5efcd9b51bc5b3148` |
| `segment1_ctx_only.bin` | `c193d96df228448a7936afbd143d34c24467936729323d1a7be3034e146735d3` |

Private integration check (requires the resources above):

```bash
python3 pblexp_macos.py check-resources
```

Public tests use synthetic fixtures and need no proprietary files:

```bash
python3 -m unittest discover -s tests -v
python3 pblexp_macos.py self-test
```

Install `requirements.txt` first. Offline mocks do not validate USB or exploit execution.
