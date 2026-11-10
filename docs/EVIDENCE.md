# Evidence index

This repository excludes the proprietary payload resources and OEM programmer
binaries. It records their hashes and the live wire observations so the
reported results can be checked without redistributing vendor firmware.

The private research workspace contains the raw PBL/IMEM dumps and the
sanitized run logs. Raw USB packet captures (pcap) were **not** saved for the
oracle run; the wire packet below is the actual device response, and the host
sequence is deterministic.

---

## 1. PBL / IMEM dumps

| Artifact | Range | Size | SHA-256 | Status |
|---|---|---:|---|---|
| `PBL-SDM710-300000-clean-2026-11-10.bin` | `0x300000..0x33c000` | 245,760 B (240 KiB) | `2736e155eb52457972ab93aeb77041f3a0a1067452147c553ee38220c7f9fb90` | clean; TX self-check OK |
| `PBL-SDM710-300000-2026-11-10.bin` | `0x300000..0x33c000` | 245,760 B | `5c3740f591852d3e50b4785d6e595b6ab4cc4e1b5027d54159a4802bd46245c0` | first dump; periodic 16-byte TX-status corruption |
| `PBL-SDM710-IMEM-2026-11-10.bin` | `0x14800000..0x14820000` | 131,072 B (128 KiB) | `204df714dba5d1822ff8834d1c0d5ad71c446c152cab513211d904fba3963eb2` | clean outside the TX packet-buffer window |

Dump method: 0xBF8 zero segment, `segment1_scan28.bin` (clean code) or
`segment1_imem.bin` (IMEM), 175 resets, segment2/3, raw read. The clean code
payload uses `pktbuf=state+0x458`; the first dump used `+0x498` and overlapped
the TX status fields.

The clean dump is the byte-accurate reference. The first dump is retained for
provenance only.

---

## 2. Payload and programmer hashes

| Artifact | SHA-256 |
|---|---|
| `segment1.bin` (pristine) | `da6cffd174d8bac3d56b7b024ff35cca6d393368f7de7a719ea3e0f2bff58b5b` |
| `oppo710_elf_header.bin` | `8b0783b70f4793cdddbce64d51775ec1b261a65968ef3087bd44aa046360ba4a` |
| `oppo710_program_headers.bin` | `fbb4b23984616972b225c48298a9f82d8d39c76b0ca304e066c095be28ead42e` |
| `segment2.bin` | `26712a9af552ca20a9594ab0f6eb96427b302388a47f7f8672c6b002fa36aa3a` |
| `segment3.bin` | `d68e5c4385f289c59469c0567718a4b127a56321cf3bb722298c58814d312692` |
| `common_zero_segment.bin` | `cb9d8ad98a67bce84c7726b113d37ba7b9a48a87431c0ad9422ffbbb85da4e51` |
| `segment1_ctx_only.bin` | `c193d96df228448a7936afbd143d34c24467936729323d1a7be3034e146735d3` |
| `segment1_postflags_v2.bin` | `9226f564e30c9be1b2e383a46f997e42dd5fa2646731206f0e998acba0be1b7d` |
| `segment1_loader_table.bin` (v1) | `f488ee5034c84a14826b2fd6c12899c11137ac75998bcff5efcd9b51bc5b3148` |
| `segment1_loader_table_v2.bin` | `2e7a9b2cddc6e478ecc8ed5ea4b23b4a3077ca8ce4ecbeb0ae8bc38d7db24b2d` |
| `segment1_loader_table_v3.bin` | `cc8f186c194d32802b100ce04edcacb1d1e5a24758f397b5be8c492bb88cb40b` |
| `segment1_skipbc4c.bin` | `7d20280f460c93ec253d1bfb7fc1635ad2dee9baead6e6f1fe2a34022ffceaa2` |
| `segment1_oracle.bin` | `299eaec923f255e38ce4aae309a3050265f21faf3daf69c051cd1e62ebbd9ef3` |
| `devprg_710` (signed OEM) | `a9fc1744e2ba010b827a8b019aede426c2a72cc264678b91ae23b82679c6f214` |
| `devprg_710_mod.bin` (one byte) | `b1c123b835a88542e4283265c716a31ecc8e71547a575414153f1b8bff473492` |

The v1/v2 loader-table payloads are historical failures: v1 called
`0x300b90` instead of the segment-relative `0x85e28b90`; v2 fixed the call but
stored the success constant as a raw instruction word (`UDF`) instead of
`movz/movk/ret`. v3 writes valid `5291fe00 72a5d900 d65f03c0` and
`52875400 72ab53a0 d65f03c0` stubs. v3 is untested.

---

## 3. Live experiments

Different modified-programmer observations are different experiments. Do not
merge them.

| ID | Host / date | Payload SHA | Image SHA | Observation |
|---|---|---|---|---|
| `W-PHASEC` | Windows `pblexp`, 2026-11-09 | `da6cffd1…58b5b` (original pblexp segment1) | `b1c123b8…3492` | full image served; `END_IMAGE_TX status=1` (historical rejection) |
| `M-SIG` | macOS native, 2026-11-10 | `9226f564…1b7d` or `2e7a9b2c…4b2d` | `a9fc1744…f214` | 181 READ_DATA64, `END_IMAGE_TX status=0`, `DONE_RESP status=1` |
| `M-MOD-PF2` | macOS native, 2026-11-10 | `9226f564…1b7d` | `b1c123b8…3492` | 181 READ_DATA64, then USB reset before `END_IMAGE_TX`/`DONE` |
| `M-MOD-LT2` | macOS native, 2026-11-10 | `2e7a9b2c…4b2d` | `b1c123b8…3492` | 181 READ_DATA64, then USB reset before `END_IMAGE_TX`/`DONE`; v2 stub was malformed |
| `M-ORA` | macOS native, 2026-11-10 | `299eaec9…d9ef3` | — | 48-byte `PBLXORACLE2026!!EXEC-PROOF-0x970…` after segment2/3; payload then loops |

The `W-PHASEC` status 1 and the newer macOS reset-before-END are both valid
for their own runs. The newer reset is not a new status-1 observation.

---

## 4. Oracle wire packet

Host sequence: the normal fixed sequence through the 0xBF8 zero segment and
175 resets, then segment2/3. The zero response is
`END_IMAGE_TX status=0x08` (`INVALID_DATA_SIZE`); it is the expected response
to the deliberate 16-byte overrun, not an image-complete success. Immediately after segment2/3 the device returned
48 bytes:

```text
PBLXORACLE2026!!EXEC-PROOF-0x9700123456789ABCDEF
```

The payload called the PBL TX primitive `FUN_00308B40` with a 0x30-byte
buffer at `0x14815000`. It did not scan code. The payload then branched to an
infinite loop, so the PBL was intentionally left hung; a cold power cycle is
the recovery.

This is execution proof for the `0x970` slot, not proof of programmer
authentication bypass.

---

## 5. Reproduction checks

At public commit `b71512b`, a fresh GitHub clone gives:

```text
python3 -m unittest discover -s tests -q
Ran 64 tests in 0.046s
OK

python3 pblexp_macos.py self-test
HOST SEQUENCE COMPLETE
SELF-TEST: PASS (offline; no device opened, mock host sequence)

python3 pblexp_macos.py ping --dry-run
configure XML (ufs): 170 B
```

The public tests use synthetic fixtures. They do not establish USB hardware
compatibility, loader handoff, programmer execution, or auth bypass.

---

## 6. Gaps

- Raw PBL/IMEM binaries are not in the public repo; only hashes and the
  private workspace.
- No raw pcap for the oracle run; the 48-byte response and host sequence are
  recorded above. A future run should capture USB traffic with `usbmon` or an
  equivalent.
- v3 loader-table and skip-BC4C are built but untested.
- The C.01 restore XML is geometry-verified but not end-to-end tested.
- No partition/GPT/RPMB/devinfo write has been made.
