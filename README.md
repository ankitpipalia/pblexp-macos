# pblexp-macos

A native **macOS/libusb** port of the Qualcomm Sahara/`pblexp` `oppo710`
workflow used on the Realme X (RMX1901, SDM710).

This is a **research and porting project**, not a bootloader-unlock tool. It
sends a fixed Sahara image-transfer sequence, serves an OEM programmer image
from the host, and can optionally send one benign Firehose `<configure>` as an
execution ping. It does **not** write partitions, GPT, RPMB, or `devinfo`.

**Live status:** the native macOS host, loader handoff, and signed-programmer
serve sequence is **validated on hardware**, and a direct TX oracle proves
the `0x970` CVE payload executes. The PBL auth bypass, modified programmer,
and bootloader unlock are **not** validated. See
[docs/FINDINGS.md](docs/FINDINGS.md) for the exact working/non-working matrix;
[docs/EVIDENCE.md](docs/EVIDENCE.md) records hashes, experiment IDs and the
oracle packet.

### Working / not working (2026-11-10)

| Area | Status |
|---|---|
| macOS 9008 enumeration, claim, bulk transport | working |
| Native host sequence through segment3 | working |
| Loader handoff + signed OEM programmer serve | working (181 READ_DATA64, DONE) |
| Firehose configure and `<power value="reset_to_edl"/>` | working while a programmer runs |
| Direct proof that the segment1 `0x970` payload executes | working (TX oracle after segment2/3) |
| PBL programmer-auth bypass / modified programmer | **not working yet** |
| Bootloader unlock, partition/GPT/RPMB write | **not attempted / not achieved** |

The signed programmer is a control, not an auth bypass. The modified
programmer is still rejected after the full image is served. Details and
live logs are in [docs/FINDINGS.md](docs/FINDINGS.md).

---

## Why a separate macOS transport

On Windows the device appears as `Qualcomm HS-USB QDLoader 9008 (COMx)` and a
serial handle works. On macOS, QDLoader 9008 is a **vendor-specific USB
interface**:

```text
VID 0x05c6  PID 0x9008
interface class/subclass 0xff/0xff; protocol 0xff, 0x10, 0x11, or 0x13
two bulk endpoints (OUT + IN)
```

Stock macOS did **not** create a `/dev/cu.usbmodem*` or tty node for the
observed interface. Apple CDC ACM matches class/subclass `0x02/0x02`; a
third-party vendor driver is a separate case. Linux `qcserial` can expose a
vendor `ttyUSB` port, which is distinct from CDC ACM. No kext, dext, or `usbfluxd` is
needed: pyusb/libusb talks to IOKit directly. See
[docs/MACOS-USB-TRANSPORT.md](docs/MACOS-USB-TRANSPORT.md).

---

## Requirements

- macOS (tested on macOS 15.8.2, arm64) or Linux
- Python 3.10+
- `pyusb` (and a libusb backend; Homebrew `libusb` is sufficient)
- `pyserial` only for the optional Windows/serial transport

```bash
python3 -m pip install -r requirements.txt
```

`qdl` is optional for independent detection (`qdl list`); it is not used for
the custom exploit sequence.

---

## Required resources (not included)

The tool needs the owned device's `oppo710` payload resources and an OEM
programmer image. These are proprietary artifacts and are **not** committed to
this repository. Put them in `resources/` (or pass `--resources DIR`):

```text
resources/oppo710_elf_header.bin
resources/oppo710_program_headers.bin
resources/segment1.bin
resources/segment2.bin
resources/segment3.bin
resources/common_zero_segment.bin  # optional: generated and hash-checked if absent
```

Expected hashes and provenance are in [resources/README.md](resources/README.md).
The signed programmer is supplied with `--image /path/to/devprg_710`.

The 48-byte Hello710 is a constant in the code; `hello710.bin` is not loaded.
Host resources are size/hash-checked before opening a transport. Programmer
data is read and checked for nonempty content; its SHA-256 is logged, but the
CLI does not independently verify its OEM signature. A custom `--segment1` requires its explicit `--segment1-hash`.

---

## Usage

```bash
# public offline tests: synthetic fixtures, no payloads or hardware
python3 -m unittest discover -s tests -v
python3 pblexp_macos.py self-test

# private resource integration / sequence inspection
python3 pblexp_macos.py check-resources
python3 pblexp_macos.py dry-run --mode all --image /path/to/devprg_710

# ping dry-run needs no payload resources
python3 pblexp_macos.py ping --dry-run

# live: detect the 9008 interface
python3 pblexp_macos.py list-ports

# host sequence only
python3 pblexp_macos.py host --transport usb

# host + handoff + serve a signed programmer, one process
python3 pblexp_macos.py all --transport usb --image /path/to/devprg_710

# custom experimental segment1 (e.g. loader-table auth candidate)
python3 pblexp_macos.py all --transport usb \
  --resources resources \
  --segment1 /path/to/segment1_loader_table.bin \
  --segment1-hash f488ee5034c84a14826b2fd6c12899c11137ac75998bcff5efcd9b51bc5b3148 \
  --image /path/to/devprg_710
```

The macOS default transport order is **USB first**, then serial. On Windows,
use `--transport serial --port COMx`.

USB device selection, including `--usb-bus` and `--usb-address`, uses the
same `UsbEdl` backend; an explicit USB selector forces USB transport. Discovery
polling uses `--port-timeout` and `--reopen-timeout`. USB reconnect retains the
bus/physical port path while allowing its address to change. If the backend
provides no port path, only the original bus/address is accepted. This selects
a USB location, not an authenticated device identity. Ambiguous targets are
rejected. Serial handoff reopens the original COM/path; automatic serial path
changes are not supported. Individual OS USB calls have their own timeouts.

CDC line-coding/control-line-state requests are disabled by default.
`--usb-cdc` enables an experimental compatibility probe; the Windows tool uses
a Qualcomm vendor driver, and its actual USB setup requests have not been
captured. Descriptor string reads are also avoided by default. Historical
`iProduct` reads returned EIO, but this does not show they caused later
Sahara timeouts.

For `serve`/`all`, exit `0` means completed Sahara when `--xml none`, or a
programmer XML response when a ping is requested. Exit `2` means accepted
image data but missing completion or the requested XML response; exit `3`
means rejection or incomplete transfer. `ping` returns `0` for a response and
`2` when no response arrives. Input, resource, or transport errors are reported
as exit `1` (argument parsing errors use `2`). Sahara completion requires a valid `DONE_RESP` with status `1`;
status `0` is pending. See [docs/IMPLEMENTATION-REVIEW.md](docs/IMPLEMENTATION-REVIEW.md)
for the review corrections and remaining hardware limits.

---

## Layout

```text
pblexp_macos.py                 native CLI
usb_edl.py                      pyusb/libusb Qualcomm EDL transport
resources/README.md             required resources and hashes (no blobs)
docs/FINDINGS.md                historical evidence and current limits
docs/IMPLEMENTATION-REVIEW.md   review corrections and public verification
docs/MACOS-USB-TRANSPORT.md     macOS 9008 transport research
docs/WINDOWS-PBLEXP-RE.md       static RE of the Windows OPPOQcomPatchTool
                                sequence, resources, serial parameters
```

---

## Safety

- No partition, GPT, RPMB, or `devinfo` writes are implemented.
- Only use this on a device you own and can recover through EDL.
- The Windows tool's fixed PBL addresses are device/SoC-specific; do not run
  this against a different model.
- The current PBL auth-bypass and unlock status is documented in
  [docs/FINDINGS.md](docs/FINDINGS.md); do not treat this as an unlock release.

## License

MIT. See [LICENSE](LICENSE).
