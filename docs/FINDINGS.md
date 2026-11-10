# Findings — evidence and current limits

Status date: 2026-11-10. Target: owned Realme X RMX1901 (SDM710), C.01,
bootloader locked. The implementation review and corrections used offline
checks only: no hardware discovery, USB probes, or storage commands.

## Current port

The CLI implements host / serve / all / ping / check-resources / dry-run /
self-test / list-ports. The `oppo710` sequence includes the `0xbf8` zero
segment and 175 individual reset writes and HELLO reads, followed by the
close / 1000 ms / reopen / loader-HELLO handoff recorded in the Windows RE.
The serve path supports READ_DATA32/64, END_IMAGE_TX and DONE_RESP; the
optional Firehose operation is a benign configure ping. No partition, GPT,
RPMB, or `devinfo` write commands exist.

The reviewed host-side defects are addressed by buffered packet-sized USB
reads, one shared USB backend, preflight resource/programmer validation,
strict host-request checks, bounded serving ranges and discovery, identity
preservation, and explicit completion status. See
[IMPLEMENTATION-REVIEW.md](IMPLEMENTATION-REVIEW.md) for the issue mapping and
verification commands. Public tests and `self-test` use synthetic fixtures;
`check-resources` is a separate private integration check. Mocks cannot
validate the native USB exchange or execution on the device.

CDC setup requests are disabled by default. `--usb-cdc` is an experimental
opt-in, not confirmed Windows compatibility. The recorded Windows COM port
uses a Qualcomm vendor driver; no capture establishes its USB setup traffic.

## Historical hardware observations

These are retained research records. The private binaries and sanitized raw
Windows logs needed to reproduce them are absent from the public checkout;
the implementation review did not independently verify them.

### Windows baseline

The recorded original OPPOQcomPatchTool / `pblexp` run loaded signed OEM
`devprg_710`: 175 reset HELLOs, 181 READ_DATA64 requests (~`0xa850c` bytes),
END_IMAGE_TX image `0xd` status `0`, DONE_RESP, and a Firehose configure
response. The recorded static analysis found a UPX-packed PE32 NativeAOT
artifact, 11 embedded resources, serial 115200 8N1 with no handshake or
DTR/RTS setters, and the explicit close / sleep / reopen handoff.

The actual HELLO bytes were not recovered from the static artifact; the
port uses captured values. Some packet-offset interpretations and the
original inference about DONE were corrected after review. See
[WINDOWS-PBLEXP-RE.md](WINDOWS-PBLEXP-RE.md).

A successful signed-programmer transfer alone does **not** demonstrate an
authentication bypass: normal Sahara loaders also load signed programmers.
A same-image cold-device control without the exploit phase is needed to
attribute any effect to the patch sequence.

### Native macOS transport

The historical record reports `05c6:9008`, a vendor-specific interface,
bulk IN `0x81` / OUT `0x01`, successful open/claim/release through
PyUSB/libusb without root, and independent `qdl` enumeration. No tty was
created by stock macOS. Apple's ACM matching is class/subclass `2/2`;
Linux `qcserial` can create a vendor `ttyUSB` port instead of CDC ACM.

The earlier transport report inferred maxpacket 512 from high-speed bulk
conventions rather than preserving the endpoint descriptor; treat the
number as unverified until a sanitized descriptor is attached. Runtime USB
buffer sizing uses the actual endpoint descriptor.

A complete native macOS host/serve run remains **unvalidated**. The recorded
first 48-byte Hello710 bulk OUT timed out. Later resets sometimes failed,
and warm `adb reboot edl` did not reliably clear the observed state. These
observations do not establish whether stale Sahara state, host transport,
or other behavior caused the failure. Descriptor `iProduct` reads returned
EIO while the device stayed enumerated; that does not establish that those
reads caused the later state. The 8-byte receive-buffer defect and aligned
OUT ZLP defect do not explain that first 48-byte write timeout.

Re-enumeration and handle replacement across Sahara / loader / Firehose are
implemented for offline testing but remain unvalidated on this hardware.
The original descriptor research and its historical commands are preserved
in [MACOS-USB-TRANSPORT.md](MACOS-USB-TRANSPORT.md).

## Separate auth and unlock research

No unsigned or modified programmer execution and no bootloader unlock have
been demonstrated. The recorded modified programmer was rejected with
END_IMAGE_TX image `0xd` status `1`.

Private firmware analysis recorded status `1` as the Sahara default at
`0x308f34`, an early return in `FUN_0030DE40` when finalize flags are unset,
and a separate programmer auth callback table registered by `FUN_0031117C`
(`0x14811620`, `0x14811658/60/68`). The loader-table patch candidate
(`segment1_loader_table.bin`, SHA-256 `f488ee50…3148`) remains unvalidated.
These firmware-specific conclusions were not independently fact-checked
without the firmware artifacts.

The historical C.01 boot-chain notes report no runtime
`Is_VERIFIED_BOOT_2()` / GPT `vbmeta` lookup, continuing VB2 and Keymaster
milestone behavior, milestone-independent `VBRwDeviceState` in ABL/DXE with
TA policy untested, and a separate pre-USB fastboot token gate at `0x311b4`.
Those are separate research findings, not evidence that this port unlocks a
device or that a transport fix bypasses secure boot. Nothing was flashed.

## Evidence still needed

Preserve sanitized endpoint descriptors, the relevant Windows USB/setup
trace, and complete cold-device native logs to investigate the unresolved
first-write timeout and handoff. Preserve a same-signed-image control
without the patch sequence before claiming an auth effect. No such hardware
validation was performed as part of these corrections; offline success
must not be reported as live success.
