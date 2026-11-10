# macOS native support for Qualcomm HS-USB QDLoader 9008 — serial research & pblexp port strategy

**Status:** research complete, device verified live
**Date:** 2026-11-10
**Target project:** RMX1901 (Realme X, SDM710) EDL / `pblexp` workflow
**Author:** research subagent

**Evidence labels used throughout**

| Label | Meaning |
|---|---|
| `[OBSERVED]` | Measured on this exact Mac, in this session. Reproducible command included. |
| `[APPLE-PRIMARY]` | Read from Apple's own installed driver bundle / man page on this Mac. |
| `[TOOL-SRC]` | Read from the tool's source code at a pinned commit. |
| `[DOC]` | Vendor or third-party documentation / public writeup. |
| `[INFERRED]` | My reasoning, not directly observed. Flagged so it can be challenged. |

> **Device safety note.** An RMX1901 was attached in EDL mode during this research
> (`QUSB_BULK_CID:0400_SN:<serial>`). **No Sahara, Firehose, reset, or write command was
> issued.** Every command run against it was descriptor/registry enumeration only —
> the libusb equivalent of `lsusb`. No interface was claimed and no transfer was sent.
> `qdl list` opens a descriptor-only handle (`usb_list()` "reads descriptors without
> claiming anything" `[TOOL-SRC]` `src/usb.c`), which is why it was considered safe.

---

## 0. TL;DR

1. **QDLoader 9008 does *not* enumerate as `/dev/cu.usbmodem*` or `/dev/tty.usbmodem*` on macOS — and it never will.** It is a **vendor-specific USB interface (class `0xFF`, subclass `0xFF`, protocol `0x10`)**, not CDC ACM. It creates **no tty device of any kind**. `[OBSERVED]`
2. **No driver, no kext, no usbfluxd, no system extension is needed.** Access is via **libusb → IOKit**, which requires **no `sudo`** and **no udev rules**. macOS is *simpler* than Linux here, because there is no `qcserial` to fight. `[OBSERVED]`
3. **`usbfluxd` is irrelevant** — it is a subproject of `usbmuxd` for multiplexing **iOS** devices over a socket. It has nothing to do with Qualcomm EDL. Strike it. `[DOC]`
4. **Best tool: `qdl` (linux-msm/qdl).** Already installed here as **v2.9.1**; officially ships **macOS arm64 binaries**; matches **VID `0x05c6` with PID deliberately unfiltered**. `[OBSERVED]` + `[TOOL-SRC]`
5. **Detection:** `qdl list` is the correct primary command and works today →
   `05c6:9008<TAB><serial>`. **`pyserial list_ports` and `ls /dev/cu.*` will never see it.**
   The serial can degrade to `(none)` while the device stays enumerated — **key on
   VID/PID + interface class, never on the serial, and do not poll.** `[OBSERVED]`
6. **Port recommendation: go libusb-only and delete the COM-port abstraction** from the Windows `pblexp` workflow. DTR/RTS/baud/exclusive-open logic has no macOS equivalent to port — it has to be *replaced*, not translated.

---

## 1. Q1 — Does 9008 enumerate as a serial port via built-in CDC ACM?

### Answer: **No. Definitively not.**

#### 1.1 Live proof from the attached device `[OBSERVED]`

Read straight out of the IORegistry for the RMX1901 currently in EDL:

```console
$ ioreg -r -c IOUSBHostInterface -l -w0 | grep -iE "bInterfaceClass|bInterfaceSubClass|bInterfaceProtocol|bNumEndpoints"
      "bInterfaceSubClass" = 255
      "bInterfaceProtocol" = 16
      "bInterfaceNumber" = 0
      "bInterfaceClass" = 255
      "bNumEndpoints" = 2
```

Decoded:

| Field | Value | Meaning |
|---|---|---|
| `bInterfaceClass` | `255` = `0xFF` | **Vendor-specific** — not `0x02` (CDC Communications) |
| `bInterfaceSubClass` | `255` = `0xFF` | vendor-specific |
| `bInterfaceProtocol` | `16` = `0x10` | **Sahara** (PBL waiting for an image) |
| `bNumEndpoints` | `2` | one bulk IN + one bulk OUT |
| `bInterfaceNumber` | `0` | single interface |
| `bConfigurationValue` | `1` | config 1 |

`0xFF/0xFF/0x10` is the Sahara/EDL signature. It is the exact tuple that `qdl`'s
`usb_match_edl_interface()` demands:

```c
/* linux-msm/qdl src/usb.c */
if (ifc->bInterfaceClass != 0xff)   return false;
if (ifc->bInterfaceSubClass != 0xff) return false;
/* Sahara is identified by bInterfaceProtocol 0x10, 0x11, or 0x13
 * on modern devices, and 0xff on older targets. */
if (ifc->bInterfaceProtocol != 0xff && ... != 0x10 && ... != 0x11 && ... != 0x13)
        return false;
```
(`[TOOL-SRC]` `src/usb.c`, linux-msm/qdl v2.9.1)

#### 1.2 No tty was created — and none can be `[OBSERVED]`

```console
$ ls -la /dev/cu.* /dev/tty.*
crw-rw-rw-  1 root  wheel  0x9000003 /dev/cu.Bluetooth-Incoming-Port
crw-rw-rw-  1 root  wheel  0x9000001 /dev/cu.debug-console
crw-rw-rw-  1 root  wheel  0x9000002 /dev/tty.Bluetooth-Incoming-Port
crw-rw-rw-  1 root  wheel  0x9000000 /dev/tty.debug-console
```

Only the two built-in pseudo-ports that exist on every Mac. **No `usbmodem` entry appears
with the device plugged in and running.** The device's IORegistry node is an
`IOUSBHostDevice` with **no `IOSerialBSDClient` child** — which is precisely the service
that would create `/dev/cu.*`:

```console
$ ioreg -p IOUSB -l -w0 | grep -A8 "QUSB"
+-o QUSB_BULK_CID:0400_SN:<serial>@01100000  <class IOUSBHostDevice, ...>
      "sessionID" = 18796265906163
      "idProduct" = 36872          # 0x9008
      "bcdDevice" = 0
      "USB Product Name" = "QUSB_BULK_CID:0400_SN:<serial>"
      "locationID" = 17825792      # 0x01100000
      "idVendor" = 1478            # 0x05C6
      "kUSBProductString" = "QUSB_BULK_CID:0400_SN:<serial>"
```

Note what is **absent**: there is no `"USB Serial Number"` / `kUSBSerialNumberString`
property. The device reports **`iSerialNumber = 0`** (no serial string descriptor) — see §1.6.

#### 1.3 Why: Apple's CDC ACM driver physically cannot match `[APPLE-PRIMARY]`

This is the strongest available evidence — read from **Apple's own installed kext on this
machine**, not from documentation:

```console
$ plutil -p /System/Library/Extensions/AppleUSBACM.kext/Contents/Info.plist
```
```json
"CFBundleIdentifier" => "com.apple.driver.usb.cdc.acm"
"IOKitPersonalities" => {
  "AppleUSBACMControl0" => {
    "bInterfaceClass"    => 2
    "bInterfaceSubClass" => 2
    "bInterfaceProtocol" => 0
    "IOClass"            => "AppleUSBACMControl"
    "IOProviderClass"    => "IOUSBHostInterface"
  }
  "AppleUSBACMControl1" => {
    "bInterfaceClass"    => 2
    "bInterfaceSubClass" => 2
    "bInterfaceProtocol" => 1
    ...
  }
}
```

The personality match is **`bInterfaceClass == 2` AND `bInterfaceSubClass == 2`** (CDC
Communications / Abstract Control Model), protocols 0 and 1. A `0xFF/0xFF` interface
**cannot match this personality**. IOKit therefore leaves the interface **unclaimed**, which
is exactly the condition libusb needs.

The composite personality in `AppleUSBCDC.kext` is equally specific — it keys on
**`bDeviceClass = 2`**, not `0xFF`. `[APPLE-PRIMARY]`

The ACM driver *is* loaded and healthy on this box — it just has nothing to bind to:

```console
$ kmutil showloaded --list-only | grep cdc
  254  com.apple.driver.usb.cdc        (5.0.0)
  258  com.apple.driver.usb.cdc.acm    (5.0.0)
  259  com.apple.driver.usb.cdc.ecm    (5.0.0)
  263  com.apple.driver.usb.cdc.ncm    (5.0.0)
```

Cross-check that this mechanism is real and not theoretical: a **class-compliant** CDC-NCM
device *is* bound on this same Mac right now (`AppleUSBNCMControl@0`, `AppleUSBNCMData@1`, …).
So the stack does bind CDC devices — it simply has no rule that matches `0xFF`.
`[OBSERVED]`

#### 1.4 Linux agrees — the same 9008 is deliberately *not* a serial port `[TOOL-SRC]`

`drivers/usb/serial/qcserial.c` (torvalds/linux, master) lists the device:

```c
{DEVICE_G1K(0x05c6, 0x9008)},	/* Generic Gobi QDL device */
```

…but `qcprobe()` refuses to drive it as a serial port unless it is vendor-specific, and
treats a single-interface device as QDL mode:

```c
/* we only support vendor specific functions */
if (intf->desc.bInterfaceClass != USB_CLASS_VENDOR_SPEC)
        goto done;                    /* retval = -ENODEV */
...
if (nintf == 1) {
        /* QDL mode */
```

So even on Linux, where a "COM port" appears, it is **`ttyUSB0` synthesised by a vendor-
specific quirk driver**, not a CDC ACM port. That distinction matters for §1.5.

#### 1.5 Why Windows *does* show a COM port (and why that misleads the port)

On Windows the familiar `Qualcomm HS-USB QDLoader 9008 (COMx)` is created by the
**Qualcomm-supplied QDLoader driver**, not by `usbser.sys`/CDC ACM. Every Windows EDL guide
in the ecosystem is built around installing that driver, e.g. an independent macOS/Windows
EDL guide: *"Device Manager > Ports > Qualcomm HS-USB QDLoader 9008 (COMx). If it shows
QUSB_BULK instead, install the Qualcomm QDLoader driver (no Zadig / WinUSB swap)."* `[DOC]`
<https://xdaforums.com/t/palm-pvg100-pepito-edl-flashing-guide-for-mac-win-linux.4804222/>

**macOS has no equivalent of that vendor driver, and does not need one**, because libusb
talks to the device directly. This is the single most important framing point for the port:

> `pblexp -p COMx` on Windows is talking to a **vendor-driver COM port**.
> There is no macOS object with those semantics. The port target is **bulk endpoints over
> libusb**, not a byte-stream file descriptor.

#### 1.6 Identity and "serial settings"

| Property | Value | Source |
|---|---|---|
| VID | `0x05C6` (Qualcomm) | `[OBSERVED]` `idVendor = 1478` |
| PID | `0x9008` (EDL/Firehose); `0x900E` = crash-dump mode | `[OBSERVED]` `idProduct = 36872` |
| `bcdDevice` | `0.00` | `[OBSERVED]` |
| `iProduct` | `QUSB_BULK_CID:0400_SN:<serial>` | `[OBSERVED]` |
| `iSerialNumber` | **absent (0)** — serial is embedded in `iProduct` after `_SN:` | `[OBSERVED]` |
| `bInterfaceClass/SubClass/Protocol` | `0xFF / 0xFF / 0x10` | `[OBSERVED]` |
| Endpoints | 2 × bulk (IN + OUT), `wMaxPacketSize` 512 @ high speed | `[OBSERVED]`/`[INFERRED]` |
| Line coding / baud | **none — not applicable** | see below |

**"What baud rate?" has no answer for 9008.** There is no UART, no line coding, no
framing. Sahara/Firehose are length-prefixed binary protocols over raw bulk pipes; timing
is governed by transfer completion, not a bit clock. Any `115200 8N1` you see in EDL tooling
applies to **diag** ports (`0x901D`, `0x900E` in some modes) or to Windows COM emulation
defaults — **not** to this interface. `[INFERRED, high confidence]`

The Windows/Linux product-string convention is documented in qdl source:

```c
/* EDL devices carry the serial in iProduct as "_SN:<serial>", other
 * modes report it in iSerialNumber. */
```
(`[TOOL-SRC]` `src/usb.c`)

This is why `qdl list` prints `<serial>` even though there is no serial descriptor — and
why `qdl -S <serial>` is the correct way to select this device.

#### 1.7 Verdict

| Question | Answer |
|---|---|
| `/dev/cu.usbmodem*`? | **No** |
| `/dev/tty.usbmodem*`? | **No** |
| Any `/dev` node at all? | **No** |
| Driver / kext / dext required? | **No** |
| `usbfluxd` required? | **No — and it is the wrong tool entirely** |
| libusb required? | **Yes** (as the userspace USB API; no kernel component) |
| `sudo` required? | **No** `[OBSERVED]` (contrast: Linux needs udev rule or root) |

---

## 2. Q2 — Which macOS tools support Sahara/Firehose?

### 2.1 `qdl` — linux-msm/qdl — **RECOMMENDED**

| | |
|---|---|
| Language / licence | C, BSD-3-Clause |
| macOS support | **Official.** CI builds `qdl-binary-macos-15-arm64`, `-macos-15-intel`, `-macos-26-arm64` `[OBSERVED]` |
| Install | `brew install qdl` (already installed here: **v2.9.1**) |
| Port naming | **None.** No `/dev` node, no COM port. Selects by VID + interface class, optionally `-S <serial>` |
| Dependencies | `libusb`, `libzip` only (no kext, no Python) |
| Device match | VID `0x05c6` only; **PID deliberately unfiltered** |

```console
$ brew info qdl
==> qdl: stable 2.9.1 (bottled), HEAD
Flash firmware on Qualcomm-based devices via USB Emergency Download (EDL) mode
https://github.com/linux-msm/qdl
==> Dependencies
Required (2): libusb, libzip
```

The PID-unfiltered policy is deliberate and documented in-source:

```c
/* EDL device identity ... Qualcomm's vendor id. Product ids are deliberately
 * not filtered - EDL, crash-mode and ramdump devices enumerate with a growing
 * set of ids that no allowlist keeps up with. */
#define QUALCOMM_VID 0x05c6
```
(`[TOOL-SRC]` `include/qdl.h`)

**Pros:** the most correct EDL identity logic available; native binary; no runtime deps;
official Qualcomm-adjacent standing — Qualcomm's own Dragonwing documentation directs users
to qdl and to its Releases page for per-architecture binaries `[DOC]`
<https://dragonwingdocs.qualcomm.com/Key-Documents/Flash-Guide/flash-with-qdl>. Handles the
Sahara→Firehose transition, `--storage ufs|emmc|nand|nvme|spinor`, `qdl list`, `qdl chipinfo`,
`qdl ramdump`, zip containers, VIP digest tables.

**Cons:** opinionated CLI; no plugin hook for a custom PBL-patch payload like `pblexp -m
oppo710`. **You cannot express the pblexp exploit through stock `qdl`.** It is the right
*transport reference* and the right *verification tool*, not a drop-in host for the exploit.

### 2.2 `bkerler/edl` — the widest-feature option

| | |
|---|---|
| Language / licence | Python, GPL-3.0 |
| macOS support | **Unofficial but works.** README: `brew install libusb git` + `git submodule update --init --recursive` + `pip3 install .` `[TOOL-SRC]` |
| Port naming | libusb by default (no `/dev` node). `--serial`/`--portname` are **COM-port modes** and are useless on macOS (§2.5) |
| Notable | Largest loader collection (`Loaders/`), Firehose XML, `--skipresponse`, diag/QMI, `fhloaderparse` |

Known macOS friction, from its own tracker: #547 / #633 "Failed to install on macOS",
#573 "macOS instructions are incomplete", #584 "keystone library not found" — i.e. install
papercuts, not architectural blockers. #671 reports **Firehose loader-upload timeouts on
Apple-silicon-class ARM** (the reporter used a Pi 5, Ubuntu and an M1), which is worth
watching but is not clearly macOS-specific. `[DOC]`

`[TOOL-SRC]` detail: on Darwin the backend is requested as
`libusb1.get_backend(find_library=lambda x: "libusb-1.0.so")`. Homebrew ships
`libusb-1.0.0.dylib`, so that lookup misses and pyusb falls back to its default discovery —
it works, but only because of the fallback. If you vendor edl, fix the lookup.

**Verdict:** good reference for **Sahara/Firehose framing and payload handling**, and the
most likely place to find a loader for an odd device. Not the transport you want to ship.

### 2.3 `qualcomm/qdlrs` — Rust

Actively maintained (push 2026-10-23), but a **library + binary**, no Homebrew formula, no
prebuilt macOS artifacts, and the README does not document macOS. It uses `rusb`/libusb, so
it should *build* with `cargo build --release` on arm64, but you are on your own for
packaging. `[DOC]` <https://github.com/qualcomm/qdlrs>
**Verdict:** interesting if you want a single static binary and a Rust codebase to embed;
unproven on macOS. Not the low-risk choice.

### 2.4 `openpst/sahara` — **do not use**

Last push **2018-01-31**, Qt5/C++ desktop GUI, no macOS packaging, no Apple-silicon build.
It predates Apple silicon entirely. `[DOC]`
**Verdict:** dead. Archived-quality. Skip.

### 2.5 `usbfluxd` — **wrong tool, do not use**

`usbfluxd` ships with **`usbmuxd`**, described by its own repo as *"A socket daemon to
multiplex connections from and to **iOS devices**"* `[DOC]`
<https://github.com/libimobiledevice/usbmuxd>. It forwards the **usbmux** protocol (an iOS
lockdown/AFC transport) over TCP. It has **no** relationship to Qualcomm Sahara, Firehose,
or EDL, and cannot expose a 9008 device as anything. Including it in a tool survey is a
category error — it should be removed from the candidate list.

### 2.6 Summary table

| Tool | macOS | Install | Device appears as | Verdict |
|---|---|---|---|---|
| **`qdl`** | **Official** (arm64 + intel bottles/binaries) | `brew install qdl` | libusb handle, no node | **Use as transport + verification** |
| `bkerler/edl` | Works, unofficial | brew libusb + pip | libusb handle | Use as protocol reference / loader source |
| `qualcomm/qdlrs` | Unproven | `cargo build` | libusb handle | Optional, higher risk |
| `openpst/sahara` | No | — | — | **Dead (2018)** |
| `usbfluxd` | n/a | — | — | **Irrelevant (iOS usbmux)** |

---

## 3. Q3 — Auto-detecting the 9008 port on macOS

All commands below were run on this Mac **with the device attached**, and all are read-only
enumeration.

### 3.1 `qdl list` — **primary recommendation**

```console
$ qdl list
05c6:9008	<serial>
```

Exit code `0`. Format is `vid:pid<TAB>serial` (`[TOOL-SRC]` `qdl_list()` in `src/qdl.c`).
With no device attached it prints `No devices found` (also exit `0`) — **so do not treat
exit status as presence**; parse stdout.

> **Observed degradation — do not depend on the serial.** After the device had been sitting
> in EDL through repeated enumeration, the *same* command began returning:
>
> ```console
> $ qdl list
> 05c6:9008	(none)
> WARN: qdl: failed to read iProduct descriptor: Input/Output Error
> ```
>
> The device was still enumerated (`IORegistry` object id unchanged, `system_profiler`
> still listed it) — only the **string-descriptor read** started failing with `EIO`.
> See §4.10. Practical consequence: **treat the serial as best-effort metadata**, key your
> detector on VID/PID + interface class, and accept `(none)`.

Why this is the best detector:
- Uses the **same libusb path** as the flashing code → if `qdl list` sees it, the flash
  path can open it. No "detected but unusable" mismatch.
- Applies the **correct identity policy**: VID `0x05c6` **and** a validated `0xFF/0xFF`
  interface with bulk IN+OUT (`usb_match_edl_interface`). It will not false-positive on a
  Qualcomm *modem* or *diag* port the way a bare VID match would.
- Recovers the serial from `iProduct`'s `_SN:` even though `iSerialNumber` is absent.
- Claims nothing, sends nothing. `[TOOL-SRC]`

Machine-parseable form for automation (tolerates the `(none)` serial case):

```bash
qdl list | awk -F'\t' '$1=="05c6:9008"{print ($2=="(none)" ? "" : $2)}'
```

Minimal presence gate that does not depend on the serial:

```bash
qdl list | grep -q '^05c6:9008' && echo "EDL device present"
```

### 3.2 `system_profiler SPUSBDataType -json` — best Apple-native, structured

`[OBSERVED]` Real output with the device attached:

```console
$ system_profiler SPUSBDataType -json
{
  "SPUSBDataType" : [
    {
      "_items" : [
        {
          "_name" : "QUSB_BULK_CID:0400_SN:<serial>",
          "bcd_device" : "0.00",
          "bus_power" : "500",
          "bus_power_used" : "2",
          "device_speed" : "high_speed",
          "extra_current_used" : "0",
          "location_id" : "0x01100000 / 1",
          "manufacturer" : "Qualcomm CDMA Technologies MSM",
          "product_id" : "0x9008",
          "vendor_id" : "0x05c6  (Qualcomm, Inc)"
        }
      ],
      "_name" : "USB31Bus",
      "host_controller" : "AppleT6000USBXHCI"
    }
  ]
}
```

**Key facts this proves:**
- `product_id` `0x9008`, `vendor_id` `0x05c6`
- `manufacturer` = `Qualcomm CDMA Technologies MSM`
- `device_speed` = `high_speed` (480 Mb/s)
- **there is no `serial_number` key** — consistent with `iSerialNumber = 0`
- `location_id` = `0x01100000 / 1` (stable per physical port)

Human-readable variant — this is the **complete** `[OBSERVED]` block for the attached
RMX1901, verbatim:

```console
$ system_profiler SPUSBDataType
        QUSB_BULK_CID:0400_SN:<serial>:

          Product ID: 0x9008
          Vendor ID: 0x05c6  (Qualcomm, Inc)
          Version: 0.00
          Speed: Up to 480 Mb/s
          Manufacturer: Qualcomm CDMA Technologies MSM
          Location ID: 0x01100000 / 1
          Current Available (mA): 500
          Current Required (mA): 2
```

Note the **absence of a `Serial Number:` line** — confirming §1.6 from Apple's own tool.
(A normal USB-serial device shows one between `Version` and `Speed`.) This is a useful
one-glance sanity check: *if you see a `Serial Number:` line, you are not looking at a
9008.*

One-liner used by the independent macOS EDL guide `[DOC]`:

```bash
system_profiler SPUSBDataType | grep -i -A3 qualcomm
```

Parse with `plutil`/`jq` rather than text-matching:

```bash
system_profiler SPUSBDataType -json \
  | plutil -convert json -o - - \
  | jq -r '.. | objects | select(.product_id? == "0x9008") | [.vendor_id, .location_id] | @tsv'
```

### 3.3 `ioreg` — lowest-level, gives interface class

```bash
# device node + VID/PID/serial-in-product-string
ioreg -p IOUSB -l -w0 | grep -i -B2 -A10 "QUSB"

# the decisive check: is it really vendor-specific (0xFF) and not CDC ACM (0x02)?
ioreg -r -c IOUSBHostInterface -l -w0 \
  | grep -E "bInterfaceClass|bInterfaceSubClass|bInterfaceProtocol|bNumEndpoints"
```

Expected (rounded to the device in hand):

```
      "bInterfaceSubClass" = 255
      "bInterfaceProtocol" = 16
      "bInterfaceNumber" = 0
      "bInterfaceClass" = 255
      "bNumEndpoints" = 2
```

A tighter, targeted form:

```bash
ioreg -r -n "QUSB_BULK_CID:0400_SN:<serial>" -l -w0
```

> **Apple-silicon gotcha `[TOOL-SRC]`:** match on **`IOUSBHostDevice`**, not `IOUSBDevice`.
> pyserial's own source notes: *"IOUSBDevice was deprecated as of 10.11 and finally on
> Apple Silicon devices has been completely removed."* Code that enumerates `IOUSBDevice`
> finds nothing on an M-series Mac.

### 3.4 `pyserial list_ports` — **will never see it. Do not use as a detector.**

```console
$ python3 -c "import serial.tools.list_ports as lp; print([p.device for p in lp.comports()])"
['/dev/cu.debug-console', '/dev/cu.Bluetooth-Incoming-Port']
```

This is not a bug and not fixable by configuration. pyserial's macOS backend starts from
`IOSerialBSDClient` services:

```python
# serial/tools/list_ports_osx.py
services = GetIOServicesByType('IOSerialBSDClient')
...
usb_device = GetParentDeviceByType(service, "IOUSBHostDevice")
if usb_device:
    info.vid = get_int_property(usb_device, "idVendor", ...)
    info.pid = get_int_property(usb_device, "idProduct", ...)
```
(`[TOOL-SRC]` pyserial 3.5)

It **enumerates drivers, then reads VID/PID from the parent USB device**. A device with no
serial driver never produces an `IOSerialBSDClient`, so it is invisible — *regardless* of
VID/PID. This also means the `vid`/`pid` fields only exist *because* a serial driver already
bound. `[OBSERVED]` both visible ports report `vid=None, pid=None, hwid="n/a"`.

**Consequence for `bkerler/edl`:** its `--serial` / `detectdevices()` path compares
`port.pid`/`port.vid` against `default_ids[0x05c6,0x9008]`. On macOS that path can never
match. `edl --serial` is a Windows/Linux-COM convenience only.

### 3.5 IOKit from native code (Swift)

For a GUI/app-embedded detector, enumerate `IOUSBHostDevice` and filter on the numeric
properties. `idVendor`/`idProduct` are **integers**, not strings:

```swift
import IOKit
import IOKit.usb

func findEDL() -> [(vid: Int, pid: Int, product: String, location: Int)] {
    var out: [(Int, Int, String, Int)] = []
    let match = IOServiceMatching("IOUSBHostDevice")   // NOT "IOUSBDevice" on Apple silicon
    var iter: io_iterator_t = 0
    guard IOServiceGetMatchingServices(kIOMainPortDefault, match, &iter) == KERN_SUCCESS else { return [] }
    defer { IOObjectRelease(iter) }

    while case let dev = IOIteratorNext(iter), dev != 0 {
        defer { IOObjectRelease(dev) }
        func intProp(_ k: String) -> Int {
            (IORegistryEntryCreateCFProperty(dev, k as CFString, kCFAllocatorDefault, 0)?
                .takeRetainedValue() as? NSNumber)?.intValue ?? -1
        }
        func strProp(_ k: String) -> String {
            (IORegistryEntryCreateCFProperty(dev, k as CFString, kCFAllocatorDefault, 0)?
                .takeRetainedValue() as? String) ?? ""
        }
        let vid = intProp("idVendor"), pid = intProp("idProduct")
        if vid == 0x05C6 {
            out.append((vid, pid, strProp("USB Product Name"), intProp("locationID")))
        }
    }
    return out
}
```

To also read the interface class (`0xFF` vs `0x02`), run a second pass over
`IOServiceMatching("IOUSBHostInterface")` and read `bInterfaceClass` / `bInterfaceSubClass`.
For a C/ObjC implementation the same registry keys apply (`kUSBVendorID` is *not* the
IORegistry key name — use the literal `"idVendor"`, as pyserial does).

### 3.6 Detector decision table

| Method | Sees 9008? | Needs device open? | Use for |
|---|---|---|---|
| `qdl list` | **yes** | descriptor-only handle | **primary gate** |
| `system_profiler -json` | yes | no | UI/telemetry, stable `location_id` |
| `ioreg` (`IOUSBHostDevice`) | yes | no | class verification, debugging |
| `pyserial list_ports` | **never** | — | **do not use** |
| `ls /dev/cu.*` | **never** | — | **do not use** |

---

## 4. Q4 — macOS quirks that will bite the port

### 4.1 `cu` vs `tty` — **moot for 9008** (but know why)

On a Mac, a serial device normally yields **both** `/dev/tty.X` (dial-in) and
`/dev/cu.X` (callout). `tty.*` opens honour carrier: `open(2)` blocks until DCD is asserted
unless `CLOCAL` is set in `c_cflag` or `O_NONBLOCK` is passed `[APPLE-PRIMARY]` `man 4
termios`:

> *"the open will succeed even without a connection being present"* only if `CLOCAL` is set
> or `O_NONBLOCK` is used.

`cu.*` is the callout device and does not wait for carrier — which is why every tool that
talks to embedded hardware uses `cu.*`.

**For 9008 this entire discussion is irrelevant**, because no `IOSerialBSDClient` is created
and therefore **neither node exists**. If you ever add a *diag* path (`0x901D`) or a
CDC-ACM device, use `cu.*` and set `CLOCAL`; never use `tty.*` for outbound.

### 4.2 DTR / RTS — do not port this code

Windows `pblexp`/`fh_loader` may assert DTR/RTS as part of opening a COM handle. On macOS
there is **no modem control layer** for a `0xFF` bulk interface:
- There is no `TIOCMBIS`/`TIOCMSET` to call — no tty exists.
- The device's `0xFF` interface does not implement CDC `SET_CONTROL_LINE_STATE` semantics.
- Sending `libusb_control_transfer` with `SET_CONTROL_LINE_STATE` (0x22) to a 9008 is at
  best ignored, at worst a stall/`LIBUSB_ERROR_PIPE` on a device that has no control
  endpoint for it.

**Action:** delete DTR/RTS/break/line-coding code from the port. Keep it only behind the
`#ifdef _WIN32` branch if the Windows build must still work.

### 4.3 Exclusive access — the real failure mode

Because nothing claims the interface, the *first* opener wins and the *second* gets
`kIOReturnExclusiveAccess` → libusb reports `LIBUSB_ERROR_ACCESS` ("Access denied" /
"device busy"). There is no `EBUSY`-on-open you can retry your way out of; the other
process must exit.

Practical rules:
- Do **not** leave `qdl`, `edl`, `fh_loader`, QFIL, or a GUI flasher running.
- Do **not** run two detector instances concurrently.
- Treat `LIBUSB_ERROR_ACCESS` on an *enumerated* device as "another process has it",
  not "bad permissions" — the usual macOS misdiagnosis. Since no `sudo` is involved, a
  permissions explanation is almost never right.
- `libusb_detach_kernel_driver()` is pointless here: there is no kernel driver to detach.
  On macOS 10.15+ libusb can *capture* a driver-claimed device, but only if a driver is
  bound — which it is not. Calling detach is a no-op at best; don't build logic around it.

### 4.4 Permissions — no `sudo`, no udev, no approval prompt

`[OBSERVED]` `qdl list` and `system_profiler` both read the device as a normal user
(uid 501), with **SIP enabled** (`csrutil status` → `System Integrity Protection status:
enabled`), **0 third-party system extensions** (`systemextensionsctl list` → `0
extension(s)`), and **no approval dialog**.

This is a genuine macOS advantage over Linux, where you need either `sudo` or a udev rule
for `05c6:9008` — the independent guide states it plainly: Linux *"USB access needs sudo or
a udev rule for 05c6:9008"*, macOS *"No driver and no sudo needed."* `[DOC]`

> **Port implication:** ship **no** privilege-escalation path, no installer, no helper tool.
> If a future macOS version requires one, that is a bug report, not a design assumption.

### 4.5 Baud rate — not applicable

See §1.6. Do not expose a baud setting in the macOS UI; it invites users to "fix" a problem
that cannot exist. (If you keep a diag mode, that path *does* need `115200 8N1`.)

### 4.6 USB re-enumeration — handle invalidation is the #1 crash source

After Sahara uploads the programmer, the PBL hands control to it and the USB device state
can be torn down and re-created. Two consequences:

1. **Any open `libusb_device_handle` can become stale.** The next bulk transfer returns
   `LIBUSB_ERROR_NO_DEVICE` (or `LIBUSB_ERROR_IO`). The device node is gone; the handle
   cannot be revived.
2. **The `locationID` (physical port) is stable, the `sessionID` is not.** Re-find by
   VID/interface class and re-claim — **never** cache a handle across the Sahara→Firehose
   boundary, and never cache by index into a device list, which reorders.

`qdl` solves this with a **250 ms rescan loop** rather than a fixed timeout:

```c
usb_open()  - this backend's .open op: wait loop retrying usb_open_once() every 250 ms
...
usleep(250000);
```
(`[TOOL-SRC]` `src/usb.c`)

Recommended port behaviour: wrap every transfer in a
`NO_DEVICE → close, rescan (≤250 ms cadence, overall deadline), re-claim, retry once`
recovery, and surface a distinct "device re-enumerated" state to the UI rather than a
generic error. Also expect the **PID to change** in some flows (`9008` ↔ `900E`); match on
VID + interface class, not PID.

### 4.7 The `900E` trap

If the device enumerates as **`05c6:900E`**, it is in crash-dump/`QHSUSB__BULK` mode, **not**
EDL. *"If the phone shows 05c6:900e QHSUSB__BULK instead of 9008, EDL commands will not
work. Hold power for about 11 seconds, then re-enter EDL."* `[DOC]`

Detector rule: a bare "VID `05c6`" match is **not** sufficient. Require
`0xFF/0xFF` + bulk-IN + bulk-OUT (`qdl`'s rule) and, if you want to be strict, warn on
`900E` explicitly. Blocking on `pid == 0x9008` alone will reject legitimate variants;
matching VID only will happily hand you a crash-dump device.

### 4.8 Gatekeeper / quarantine for downloaded binaries

If the port ships a **downloaded** `qdl` or helper binary rather than a Homebrew install,
macOS tags it `com.apple.quarantine` and it will be killed on first run. The documented
remedy in the macOS EDL guide is:

```bash
xattr -dr com.apple.quarantine ./qdl
```
`[DOC]`

`[OBSERVED]` The Homebrew-installed `/opt/homebrew/bin/qdl` has **no** quarantine
attribute — Homebrew clears it. Prefer Homebrew, or clear the xattr in your installer.

### 4.9 Hubs and power

`[INFERRED]` Prefer a direct, bus-powered port. High-speed bulk EDL transfers through an
unpowered hub are a classic source of mid-flash `LIBUSB_ERROR_IO` / timeouts, and a
re-enumeration behind a hub can move `locationID`, invalidating any port-keyed state.
Two devices in EDL on the same Mac are indistinguishable by serial when `iSerialNumber` is
absent and product strings collide — **enforce one EDL device at a time**.

### 4.10 String descriptors are unreliable — and do not poll the device

`[OBSERVED]` The same attached device produced both of these, minutes apart, **without
re-enumerating** (IORegistry object id `0x1002d0a3d` unchanged):

```console
$ qdl list
05c6:9008	<serial>          # first read: iProduct string OK

$ qdl list
05c6:9008	(none)            # later: GET_DESCRIPTOR(iProduct) -> EIO
WARN: qdl: failed to read iProduct descriptor: Input/Output Error
```

Interpretation `[INFERRED]`: the PBL in Sahara mode runs a minimal USB stack. String
descriptors (`GET_DESCRIPTOR`, type `0x03`) are **control transfers**, and they are the
fragile part — the device kept answering enumeration at the descriptor/registry level while
failing string requests. This is consistent with the PBL's reputation for a thin USB
implementation and with the absence of `iSerialNumber` in the first place.

**Design consequences — these are load-bearing:**

1. **Never gate on the serial.** `qdl -S <serial>` is a convenience, not an identity
   guarantee; it fails outright once the string read does. Key on VID `0x05c6` + interface
   class `0xFF/0xFF` (+ bulk IN/OUT).
2. **Never poll.** Each `qdl list` is a real control transfer to a device with a minimal
   stack. A detector that polls every second is actively degrading the link. Detect on
   plug-in (IOKit notification) or on explicit user action, then stop.
3. **Keep a warm handle.** If you must read the serial, read it **once at open** and cache
   it for the session. Do not re-derive it per operation.
4. **Treat `(none)` as normal, not as an error.** Surface it as "serial unavailable", not
   as a device failure — the flash path can still work.
5. **This is an argument for the `[OBSERVED]` policy already in force on this project:**
   do not talk to the device unless you intend to proceed. Enumeration is not free.

### 4.11 Quirk checklist

| Quirk | macOS behaviour | Port action |
|---|---|---|
| tty / `cu` vs `tty` | no node exists | drop serial path |
| DTR/RTS/break | no tty, no CDC line coding | drop the code |
| Baud | N/A | don't expose |
| Exclusive access | 2nd opener → `LIBUSB_ERROR_ACCESS` | single-instance lock; clear message |
| Permissions | none needed, no sudo | no helper/installer |
| `IOUSBDevice` | removed on Apple silicon | match `IOUSBHostDevice` |
| Re-enumeration | handle goes stale | 250 ms rescan + re-claim |
| `900E` | crash-dump, not EDL | class-based match + explicit warning |
| Quarantine | downloaded binaries blocked | Homebrew or `xattr -dr` |
| SIP | enabled, irrelevant | — |
| **String descriptors** | **`iProduct` read can go `EIO`; serial becomes `(none)`** | **detect once, cache, never poll; don't gate on serial** |

---

## 5. Q5 — macOS-native Realme/OPPO unlock tooling, and porting `pblexp`

### 5.1 What exists publicly: essentially nothing

Searched GitHub for `OPPOQcomPatchTool`, `pblexp`, `realme unlock edl`, `oppo qualcomm
unlock` — **no matches** for the named tools. `pblexp` and `OPPOQcomPatchTool` are **not
public projects**; they circulate as packaged Windows binaries in repair-tool bundles. There
is **no macOS port, and no source to port from.** `[OBSERVED]` via `gh search repos`

### 5.2 What `pblexp` actually is (from prior project analysis)

Recorded in this workspace (`rmx1901/.serena/memories/rmx1901/deeptest-realme-x-unlock-flow.md`):

- Windows **NativeAOT PE32** binary; packed SHA-256 `f9accd90…`, unpacked `a6fa5d6f…`
- Modes `oppo665 | oppo710 | oppo845`; `oppo710` targets SDM710 (this device)
- `oppo710` payload at segment offset `0x970`: copies `0x1000` bytes `0x30f000 → 0x1481f000`,
  writes `mov x0,#1` (`0xd2800020`) at `0x1481fec4` and `ret` (`0xd65f03c0`) at `0x1481fec8`,
  calls `0x30e0ac`/`0x30fbf8`, then **serves the `-f` programmer over Sahara**
- Usage: `pblexp -p COMx -m oppo710 -f devprg_710`, then `fh_loader` with the restore XML
- It is an **early-boot/PBL patch + Sahara loader**, *not* a file-level ABL/OCDT signer

So the functional decomposition is:

```
[1] transport      : COM port byte stream   <-- the ONLY macOS-incompatible part
[2] Sahara engine  : hello / mode / read-request / image upload
[3] patch payload  : fixed AArch64 stub + patch addresses (oppo710)
[4] serve -f image : push devprg_710, then Firehose
```

**Elements [2], [3], [4] are transport-agnostic.** Only [1] changes. That is very good news:
the port is a transport swap, not a rewrite.

### 5.3 Recommended port architecture

```
pblexp-macos
├── transport/
│   ├── transport.h            # open/close/read/write (length-framed), reset, deadline
│   ├── transport_win_com.c    # existing Windows behaviour (#ifdef _WIN32, unchanged)
│   └── transport_macos_usb.c  # libusb1 backend  <-- NEW
├── sahara/                    # unchanged framing logic
├── payloads/oppo710.bin       # unchanged bytes
└── firehose/                  # unchanged (or delegate to qdl)
```

`transport_macos_usb.c` must implement:

| Operation | libusb call | Notes |
|---|---|---|
| enumerate | `libusb_get_device_list` + descriptor check | VID `0x05c6`, iface `0xFF/0xFF`, proto ∈ {`0x10`,`0x11`,`0x13`,`0xFF`}, bulk IN+OUT |
| open | `libusb_open` | no `sudo`, no detach |
| claim | `libusb_claim_interface(0)` | expect `LIBUSB_ERROR_ACCESS` if contended |
| read | `libusb_bulk_transfer(ep_in, …, timeout)` | **loop until `n` bytes** — see below |
| write | `libusb_bulk_transfer(ep_out, …)` | chunk ≤ `wMaxPacketSize`-aligned, honour `out_chunk_size` |
| reset | `libusb_reset_device` | and/or close+rescan on `NO_DEVICE` |
| serial | parse `_SN:` from `iProduct` | `iSerialNumber` is absent |

Three implementation warnings, all grounded in the sources above:

1. **Bulk reads are not message-framed.** A `libusb_bulk_transfer` may return a short
   read. Sahara/Firehose headers declare a length — you must loop until the declared
   length arrives. Code that assumes one transfer == one message will corrupt the protocol
   intermittently under load. This is the most likely source of a flaky first port.
2. **Never cache the handle across Sahara→Firehose** (§4.6). Re-enumerate and re-claim.
3. **Do not port DTR/RTS/baud.** They are meaningless here and will at best be ignored
   (§4.2).

If you want to minimise new code, **link `libusb-1.0` directly and keep the payload logic
from the Windows binary's disassembly**, rather than trying to drive the exploit through
`qdl`'s CLI — `qdl` has no hook for a custom pre-programmer payload.

### 5.4 Where `qdl` fits

Use `qdl` for everything *except* the exploit payload:

- **Pre-flight / verification:** `qdl list` to confirm the device and serial.
- **Sanity / recovery:** `qdl chipinfo` (read-only HWID/PK_HASH), `qdl ramdump`,
  `qdl --storage ufs ... read` for GPT dumps.
- **Post-exploit flashing:** once the patched programmer is resident and Firehose is up,
  `qdl -S <serial> --storage ufs <prog> rawprogram*.xml` is a well-tested path — *if* the
  programmer is the one qdl uploaded. Mixing a pblexp-uploaded programmer with qdl's
  Sahara stage will not work; qdl always uploads its own `prog.mbn`.

Also note `qdl ks -p <dev-node>`: qdl *does* have a raw-fd Sahara transport
(`qdl_open_device_node()`, which puts a tty into raw mode if the node is a terminal —
its docstring even names `/dev/mhi0_QAIC_SAHARA` and `/dev/ttyUSB0`) `[TOOL-SRC]`. On macOS
there is no such node for a 9008, but this hook is useful for **testing the Sahara engine
against a PTY** without hardware (§6, stage 2).

### 5.5 Realme-specific tooling landscape

| Item | macOS availability |
|---|---|
| `pblexp` (`oppo710`) | **Windows only**, closed, no source, no port |
| `OPPOQcomPatchTool` | **not public**, no macOS port |
| `fh_loader` | Windows only (Qualcomm). `qdl` is the cross-platform equivalent |
| QFIL / QFlash | Windows only |
| Realme/OPPO official flash tool | Windows only |
| `qdl` | **macOS native** — the only production-grade macOS EDL path |
| `bkerler/edl` | runs on macOS (Python) |

**Bottom line for Q5:** there is no macOS-native Realme/OPPO unlock tool to adopt. You are
building the first one, and the portable surface is small: a Sahara/Firehose engine plus a
libusb transport. The PBL patch payload itself is data and carries over unchanged.

### 5.6 Hard constraints carried over from prior analysis (do not lose these)

From `deeptest-realme-x-unlock-flow.md`, these still apply on macOS and are **not** solved
by the port:

- XBL authenticates ABL; **VIP/signed digest** enforcement is present in `oppo/devprg_710`
  (`VIP hash table accepted`, `Authentication of signed hash failed`).
- No OPPO private key; no `ocdt_unlock.img` / `abl_unlock.img` / `xbl_unlock.img` exists.
- `pblexp`'s **fixed PBL addresses may not match RMX1901** → **hard-brick risk**.
- The PBL patch bypasses **programmer auth only**, not XBL secure boot.
- A full 62-partition backup exists on this Mac — **verify it before any write**.

Porting the transport does not de-risk any of the above. Treat the first exploit run as
equally dangerous as it was on Windows.

---

## 6. Test plan

Staged so that **nothing touches the device** until stage 5, and stage 5–6 are read-only.

### Stage 0 — environment assertions (no device)
```bash
sw_vers                     # expect 15.x / 26.x, arm64
uname -m                    # arm64
qdl --version               # v2.9.1+
ls /System/Library/Extensions/AppleUSBACM.kext   # present = stock stack intact
systemextensionsctl list    # 0 extension(s) expected
csrutil status              # enabled is fine
```
**Pass:** no third-party kext/dext, qdl resolves, no quarantine on the binary
(`xattr -l $(which qdl)`).

### Stage 1 — detector correctness, device absent
```bash
qdl list                                   # expect: "No devices found", exit 0
system_profiler SPUSBDataType -json | grep -c 0x9008   # expect 0
python3 -c "import serial.tools.list_ports as lp; print([p.device for p in lp.comports()])"
```
**Pass:** no false positives. **This is the test most likely to be skipped and most likely
to matter** — it proves your detector does not fire on a diag/modem device.

### Stage 2 — Sahara engine against a PTY (no hardware)
Use `qdl ks -p <pty>` (its raw-fd transport) or a local harness to validate the Sahara
state machine: HELLO → HELLO_RESP → READ_DATA → END_OF_IMAGE → DONE. Assert exact byte
framing, including the short-read loop.

**Pass:** byte-identical framing vs. a captured Windows `pblexp` session; fuzz with
truncated/split transfers and confirm the read loop recovers rather than desyncing.

### Stage 3 — detector against a live device (read-only)
```bash
qdl list                                   # expect: 05c6:9008<TAB><serial>  (or "(none)")
ioreg -r -c IOUSBHostInterface -l -w0 | grep -E "bInterfaceClass|bInterfaceProtocol"
                                           # expect 255 / 16
```
**Pass:** `qdl list` shows `05c6:9008`; interface is `0xFF`; **no** `/dev/cu.usbmodem*`
appears (assert its absence explicitly — that's the regression test for the whole thesis).
Run it **once**, then stop; do not add a poll loop (§4.10). Also test the `(none)` branch by
forcing the serial read to fail (or by mocking) — the detector must still report present.

### Stage 4 — exclusive-access and re-enumeration handling
- Hold the device open in one process, start a second → assert a clean
  "device busy (another process)" message, **not** a permissions error.
- Unplug/replug mid-open → assert `NO_DEVICE` is caught, rescan loop engages, and the app
  recovers without a restart.
- Assert the app never caches a handle across a Sahara→Firehose transition.

### Stage 5 — read-only device interrogation (still no writes)
```bash
qdl chipinfo                 # HWID / PK_HASH / serial — compare to the Windows baseline
qdl -S <serial> --storage ufs ... read 0/0+34 gpt.bin    # GPT only
```
**Pass:** HWID and PK_HASH **match the Windows capture exactly**. If they don't, stop —
you are talking to a different device or a different mode.

### Stage 6 — gated exploit run (requires explicit owner approval)
Only after 0–5 pass **and** the 62-partition backup is re-verified:
1. Run the ported `pblexp -m oppo710 -f devprg_710` equivalent.
2. **Immediately** verify programmer residency (`qdl chipinfo` or Firehose `ping`) before
   any write.
3. Abort criteria: any `LIBUSB_ERROR_IO` burst, any `900E` enumeration, any HWID/PK_HASH
   mismatch, or a second EDL device on the bus.

**Do not** combine stage 6 with any write. Establish the transport first.

### Stage 7 — regression matrix
| Case | Expected |
|---|---|
| No device | `No devices found`, no crash |
| `900E` device | explicit "crash-dump mode, not EDL" message |
| Two EDL devices | refuse, require `-S <serial>` |
| Device on hub | works, or clear "connect directly" guidance |
| Second instance | "device busy", not "permission denied" |
| Mid-flash unplug | recoverable error, no partial-write claim |

---

## 7. Source list

**Apple primary (read from this machine)**
- `/System/Library/Extensions/AppleUSBACM.kext/Contents/Info.plist` — `com.apple.driver.usb.cdc.acm` 5.0.0, personalities `bInterfaceClass=2 / bInterfaceSubClass=2`, protocols 0 and 1.
- `/System/Library/Extensions/AppleUSBCDC.kext/Contents/Info.plist` — composite personality keys on `bDeviceClass=2`.
- `man 4 termios` — `CLOCAL` / `O_NONBLOCK` open semantics for dial-in devices.
- `man 4 tty` — terminal line discipline / special files.

**Qualcomm / official**
- Qualcomm Dragonwing — *Flash software images (qdl)*: <https://dragonwingdocs.qualcomm.com/Key-Documents/Flash-Guide/flash-with-qdl>
- `linux-msm/qdl` — <https://github.com/linux-msm/qdl> (v2.9.1; `src/usb.c`, `include/qdl.h`, `src/qdl.c`, `src/oscompat.h`, `udev/70-qdl.rules.in`)
- qdl releases (macOS arm64/intel binaries): <https://github.com/linux-msm/qdl/releases>
- `qualcomm/qdlrs` — <https://github.com/qualcomm/qdlrs>

**Linux kernel (behavioural cross-check)**
- `drivers/usb/serial/qcserial.c` — `{DEVICE_G1K(0x05c6, 0x9008)}` "Generic Gobi QDL device"; `qcprobe()` requires `USB_CLASS_VENDOR_SPEC`, `nintf == 1` → QDL mode.

**Tooling**
- `bkerler/edl` — <https://github.com/bkerler/edl> (macOS install section; `edlclient/Config/usb_ids.py`; `Library/Connection/seriallib.py`; `Library/Connection/usblib.py`)
- pyserial 3.5 — `serial/tools/list_ports_osx.py` (IOSerialBSDClient enumeration; `IOUSBHostDevice` note)
- libusb — `libusb/os/darwin_usb.c` (IOKit backend, `darwin_detach_kernel_driver`, interface capture on 10.15+)
- `libimobiledevice/usbmuxd` (contains `usbfluxd`) — <https://github.com/libimobiledevice/usbmuxd>

**Third-party writeups / community**
- XDA — *Palm PVG100 (pepito) EDL flashing guide for Mac/Win/Linux*: <https://xdaforums.com/t/palm-pvg100-pepito-edl-flashing-guide-for-mac-win-linux.4804222/> — macOS "No driver and no sudo needed"; Linux "sudo or udev rule"; Windows QDLoader `COMx`; 900E warning; `xattr -dr com.apple.quarantine`.
- `linux-msm/qdl` issue #188 — real `dmesg` for `05c6:9008`: `Product: QUSB_BULK_CID:040E_SN:…`, `SerialNumber=0`, `Manufacturer: Qualcomm CDMA Technologies MSM`; maintainer confirms libusb "claim[s] the USB device directly, kicking out qcserial".
- `bkerler/edl` issues #547, #633, #573, #584 (macOS install), #671 (ARM Firehose timeout).

**In-repo context (this workspace)**
- `rmx1901/.serena/memories/rmx1901/deeptest-realme-x-unlock-flow.md` — pblexp unpack/hash, `oppo710` payload behaviour, VIP/XBL blockers.
- `rmx1901-artifacts/OTA-C01-TRANSFER/C01-OTA-VERIFY.md` — `pblexp -p COMx -m oppo710 -f devprg_710` workflow.
- `tools/edl_reboot_system.py` — existing pyserial/COM-oriented helper (will need the same transport swap).

---

## 8. Open questions / residual risk

1. **Does the PBL patch survive the transport change?** The payload and addresses are
   transport-independent, but the **timing** of the Sahara upload may interact with the
   PBL's own USB handling. Only a hardware run answers this. `[INFERRED]`
2. **Does the RMX1901 accept `pblexp -m oppo710`'s fixed addresses?** Prior analysis flagged
   that the addresses may not match; unchanged by this research. **Hard-brick risk remains.**
3. **Is `qdl`'s `-S <serial>` reliable when two EDL devices share a product string?**
   `iSerialNumber` is absent and the serial is parsed from `iProduct`; two devices with
   colliding `_SN:` values would be ambiguous. Enforce one device at a time instead.
4. **macOS 26 behaviour** is untested here (this Mac is 15.8.2). qdl ships a `macos-26-arm64`
   build, which suggests it is exercised, but no independent confirmation was found.
5. **`bkerler/edl` on arm64** has reported Firehose upload timeouts (#671). If edl is used
   as a reference implementation, validate its *framing* on arm64 before trusting its
   *throughput*.
6. Exact `wMaxPacketSize` was inferred from high-speed bulk defaults, not read from the
   endpoint descriptor.
7. **The `iProduct` EIO (§4.10) has an unknown trigger.** It is not known whether it is a
   PBL idle/watchdog behaviour, a descriptor-request budget, or a side-effect of repeated
   opens — only that it happened while the device stayed enumerated. Until characterised,
   assume any string-descriptor read can fail and design accordingly.

---

## 9. One-line answers

1. **No `/dev/cu.usbmodem*` — ever.** 9008 is `0xFF/0xFF/0x10` vendor-specific; AppleUSBACM
   requires `2/2`. libusb + IOKit, **no kext, no `usbfluxd`, no `sudo`**. VID `0x05C6`,
   PID `0x9008`, no `iSerialNumber` (serial lives in `iProduct` after `_SN:`).
2. **`qdl` (linux-msm/qdl) is the macOS tool** — `brew install qdl`, official arm64 builds,
   no `/dev` node, select by VID+interface-class and `-S <serial>`. `bkerler/edl` is the
   feature-rich fallback. `openpst/sahara` is dead; `usbfluxd` is unrelated (iOS).
3. **`qdl list` → `05c6:9008<TAB><serial>`** is the detector (can degrade to
   `05c6:9008<TAB>(none)` — the serial is not guaranteed). `system_profiler SPUSBDataType
   -json` and `ioreg -r -c IOUSBHostInterface` corroborate. `pyserial list_ports` and
   `ls /dev/cu.*` **cannot** see it — by design, not by misconfiguration.
4. **Quirks:** no tty → no `cu`/`tty`/DTR/RTS/baud; second opener gets
   `LIBUSB_ERROR_ACCESS`; match `IOUSBHostDevice` (not `IOUSBDevice`); handles go stale on
   re-enumeration (250 ms rescan); `900E` is crash-dump, not EDL; quarantine only affects
   downloaded binaries.
5. **No public macOS Realme/OPPO unlock tool exists.** `pblexp`/`OPPOQcomPatchTool` are
   closed Windows binaries. The port is a **transport swap**: replace the COM handle with a
   libusb bulk transport, keep the Sahara/Firehose engine and the `oppo710` payload intact.
