# pblexp-macos

A native **macOS/libsub** port of the Qualcomm Sahara/`pblexp` `oppo710`
workflow used on the Realme X (RMX1901, SDM710).

This is a **research and porting project**, not a bootloader-unlock tool. It
sends a fixed Sahara image-transfer sequence, serves an OEM programmer image
from the host, and can optionally send one benign Firehose `<configure>` as an
execution ping. It does **not** write partitions, GPT, RPMB, or `devinfo`.

**Live status:** native macOS USB enumeration/claim works; the full live
host/serve sequence is **not yet validated**. See
[docs/FINDINGS.md](docs/FINDINGS.md) for the exact working/non-working matrix.

---

## Why a separate macOS transport

On Windows the device appears as `Qualcomm HS-USB QDLoader 9008 (COMx)` and a
serial handle works. On macOS, QDLoader 9008 is a **vendor-specific USB
interface**:

```text
VID 0x05c6  PID 0x9008
interface class/subclass/protocol 0xff/0xff/0xff (or 0x10/0x11/0x13)
two bulk endpoints (OUT + IN)
```

macOS does **not** create a `/dev/cu.usbmodem*` or tty node for it, and the
Apple CDC ACM driver only matches class 0x02. No kext, dext, or `usbfluxd` is
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
resources/common_zero_segment.bin
resources/hello710.bin
```

Expected hashes and provenance are in [resources/README.md](resources/README.md).
The signed programmer is supplied with `--image /path/to/devprg_710`.

If a resource is missing, the tool refuses before touching the device.

---

## Usage

```bash
# offline checks (resources required)
python3 pblexp_macos.py self-test
python3 pblexp_macos.py check-resources
python3 pblexp_macos.py dry-run --mode all

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

Do not run descriptor probes (`list-ports`, `qdl list`) immediately before a
live host run on this PBL; its minimal USB stack can be disturbed by string
descriptor control transfers. `usb_edl` avoids them by default.

---

## Layout

```text
pblexp_macos.py                 native CLI
usb_edl.py                      pyusb/libusb Qualcomm EDL transport
resources/README.md             required resources and hashes (no blobs)
docs/FINDINGS.md                what works / what does not
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
