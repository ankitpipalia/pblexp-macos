# Findings — what works and what does not

Status date: 2026-11-10. Device: owned Realme X RMX1901 (SDM710), C.01,
bootloader locked. No partition/GPT/RPMB write was performed during this work.

## Working

### Windows baseline (reference)

- The original Windows `OPPOQcomPatchTool`/`pblexp` sequence loads the signed
  OEM programmer `devprg_710` successfully.
- Observed live:
  - 175 reset HELLOs;
  - the programmer is served fully (181 `READ_DATA64` requests, ~0xa850c bytes);
  - `END_IMAGE_TX image=0xd status=0`;
  - `DONE_RESP`;
  - a benign Firehose `<configure>` gets a real programmer response.
- Windows-tool RE is complete:
  - UPX-packed PE32, NativeAOT;
  - 11 embedded resources, all extracted and hashed;
  - serial 115200 8N1, no handshake, DTR/RTS false;
  - exact sequence and the close + 1000 ms + reopen + loader-HELLO handoff.
  See [WINDOWS-PBLEXP-RE.md](WINDOWS-PBLEXP-RE.md).

### Native macOS transport

- QDLoader 9008 enumerates on macOS as `05c6:9008`, vendor-specific interface,
  bulk IN 0x81 / OUT 0x01, max packet 512.
- No `/dev/cu.*` or tty node exists; Apple CDC ACM cannot bind class 0xFF.
- `usb_edl.UsbEdl` finds, opens, claims, and releases the interface through
  pyusb/libusb without root, kext, or usbfluxd.
- Descriptor enumeration is confirmed live; qdl independently sees the same
  `05c6:9008`.
- Offline tests pass:
  - `self-test` (in-memory transport, 175 individual reset writes/reads,
    packet parsing, serving);
  - `check-resources` (pristine and custom segment1 hashes);
  - `dry-run host/all/serve`;
  - `list-ports` reports both usb_edl and qdl.

### Port implementation

- Native CLI with host / serve / all / ping / check-resources / dry-run /
  self-test / list-ports.
- Sequence preserved from the Windows tool, including 0xbf8 zero segment and
  175 *individual* 0x13 writes with a 0x30 HELLO read after each.
- Loader serve handles `READ_DATA32/64`, `END_IMAGE_TX`, `DONE`, and a benign
  Firehose configure.
- Custom experimental segment1 is supported with an explicit SHA-256.
- No storage-write commands exist in the tool.

## Not working / open

### Live native host sequence

- A live `host`/`all` run on macOS has **not** completed. The first Hello710
  bulk OUT transfer times out.
- The device was repeatedly left in a Sahara error state by earlier failed
  runs. `qdl reset` sometimes acknowledged, then later returned
  `SAHARA: no reset response from device`; a warm `adb reboot edl` did not
  clear it reliably.
- Because the PBL is wedged, these timeouts do not yet distinguish:
  - a stale PBL/Sahara state;
  - a libusb OPEN/claim/transfer issue;
  - a missing Windows-driver class request.
- Current mitigations already in the port:
  - no `Device.describe()` (fixed);
  - no `set_configuration()` reset;
  - no descriptor-string reads by default;
  - endpoint clear-halt and 0.5 s settle after claim;
  - CDC line-coding/control-line-state requests mirrored from usbser.
- The next diagnostic is a minimal C/libusb Hello probe on a cold EDL, then a
  cold `all` run without any prior descriptor probe.

### USB re-enumeration/handoff

- The native `all` path closes, sleeps, reopens, sends the loader HELLO, and
  serves the programmer, but this has not been observed live on macOS.
- USB handle invalidation across Sahara -> loader/Firehose is untested.

### PBL programmer auth bypass

- The signed programmer loads; a modified programmer is rejected with
  `END_IMAGE_TX image=0xd status=1`.
- Static RE found:
  - status 1 is the Sahara state-machine default at `0x308F34`;
  - the actual early return is in `FUN_0030DE40` when the finalize flags are
    unset;
  - the programmer loader has a separate auth callback table registered by
    `FUN_0031117C` (`0x14811620`, `0x14811658/60/68`).
- Best untested candidate: patch that table after registration, before
  `FUN_0030E58C`, with stubs returning `0x2EC88FF0` / `0x5A9D3AA0`
  (`segment1_loader_table.bin`, SHA `f488ee50…3148`).
- No unsigned/modified programmer has executed.

### Bootloader unlock

- **No unlock was achieved.** Device state remains locked.
- The ABL NO_AVB/Keymaster route is closed for C.01:
  - no runtime `Is_VERIFIED_BOOT_2()`/GPT `vbmeta` lookup;
  - VB2 still runs and sends the Keymaster milestone;
  - `VBRwDeviceState` is milestone-independent in ABL/DXE, but TA policy is
    untested;
  - the pre-USB fastboot token gate (`0x311B4`) is independent of RPMB/devinfo
    state.
- Boot-chain design notes are separate from this port; nothing was flashed.

## Evidence and reproducibility

- Windows signed baseline: 181 READ_DATA, END_IMAGE_TX status 0, DONE_RESP,
  Firehose configure response.
- Native macOS detection: `05c6:9008`, bulk 0x81/0x01, maxpacket 512; qdl list
  agrees.
- The device serial is intentionally omitted from this public document.
- The Windows-tool resource hashes and sequence are in
  [WINDOWS-PBLEXP-RE.md](WINDOWS-PBLEXP-RE.md); macOS transport evidence is in
  [MACOS-USB-TRANSPORT.md](MACOS-USB-TRANSPORT.md).

## Next steps

1. Cold power-off (not warm `adb reboot edl`) and run a minimal C/libusb
   Hello test, then the native `all` sequence with no descriptor probes.
2. If live host/serve works, test the loader-table auth candidate with the
   modified programmer.
3. If the table patch passes, move to the separate boot-chain/RPMB work; keep
   stock XBL and use a host-loaded modified XBL or a RAM-only hook.
