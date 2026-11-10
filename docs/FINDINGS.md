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

A native macOS host sequence completes through segment3 after the
initial-HELLO drain fix. The complete host/serve run is now **validated on
hardware** with the signed OEM `devprg_710`:

```text
host: initial RX 0x30 B HELLO drained; Hello710; header; phdrs; segment1;
      zero END_IMAGE_TX image=0xd status=0x8; 175 reset HELLOs; segment2+3
handoff: USB bus=1 address=2 ports=(1,)
serve: initial loader HELLO drained before LOADER_HELLO; 181 READ_DATA64
       requests; 0xa850c bytes served; END_IMAGE_TX image=0xd status=0x0;
       DONE_RESP status=1
Firehose: configure response observed (programmer build 2019-03-04);
          power reset returned ACK
```

The serve half needed the same unsolicited-HELLO drain as the host half.
The Windows COM open consumes that packet; the libusb path must drain it
before writing LOADER_HELLO, or the loader never issues READ_DATA. The
historical first 48-byte Hello710 bulk OUT timeout had the same cause.

The signed-programmer run proves the native macOS host, loader handoff, and
Firehose programmer path. It does **not** prove the PBL auth bypass: a
normal, signed programmer loads without the exploit patch. The modified-
programmer and table-candidate results are recorded in
[EVIDENCE.md](EVIDENCE.md); the corrected v3 table candidate is not yet
tested.

Descriptor `iProduct` reads returned EIO while the device stayed enumerated;
that does not establish that those reads caused the later state. The 8-byte
receive-buffer defect and aligned OUT ZLP defect do not explain the first
48-byte write timeout.

Re-enumeration and handle replacement across Sahara / loader / Firehose are
now exercised live through the signed-programmer run. Recovery after a
programmer power reset still needs a physical power-on on this unit. The
original descriptor research and its historical commands are preserved in
[MACOS-USB-TRANSPORT.md](MACOS-USB-TRANSPORT.md).

### Payload execution oracle (2026-11-10)

A direct USB-TX oracle payload proved that the CVE payload at segment1
offset `0x970` executes on the C.01 PBL.  The host sent the normal fixed
sequence through the zero segment and 175 reset HELLOs, then segment2 and
segment3.  Immediately after segment2/3 the device sent a 48-byte packet:

```text
PBLXORACLE2026!!EXEC-PROOF-0x9700123456789ABCDEF
```

The oracle payload called the PBL TX primitive at `0x308b40`; it did not
scan for a code pattern.  This is the first direct proof of payload
execution on this target, and it shows that the `0x970` slot runs **after**
segment2/3, not at the zero-segment/END_IMAGE_TX point.  The earlier magic
payloads used a code-pattern scan and did not produce this proof.

The oracle also gives a repeatable way to test whether a candidate payload
reached `0x970`: put a unique TX packet in the payload and look for it
after segment2/3.  A candidate that is never reached looks identical to a
signed-programmer control.

### Auth candidates (2026-11-10)

The earlier postflags and loader-table payloads contained a stub-call bug:
they called `0x300b90` instead of the segment-relative stub.  The segment1
image's ELF VA is `0x85e28000`, but its first instructions are a trampoline
that copies the phase payload to `0x149ff000` and branches there; payload
offset X runs at `0x149ff000 + (X - 0x970)`.  The stub call is PC-relative
(`bl 0xb90`), so it lands at `0x149ff720`; the earlier absolute-target
assumption was wrong.

The first corrected loader-table payload still had a second bug: its
resident "success stub" stored `0x2ec88ff0` directly as an instruction
word, which decodes as `UDF`, not `movz/movk/ret`.  v3 writes the valid
three-word stubs, but the table it patches (`0x14811620/58/60/68`) has
**zero references** in the PBL and is all-zero in live IMEM, so v3 (and
v4–v6) cannot affect rejection.  The table is dead code; this route is
closed.

The modified `devprg_710_mod.bin` (one benign string byte changed) still
serves all 181 READ_DATA64 requests (`0xa850c` bytes), then the device
resets before `END_IMAGE_TX`/`DONE_RESP`; no modified-programmer execution,
auth bypass, or unlock is proven.  The served image is not proof of
acceptance: the normal signed control also serves 181 requests and then
gets `END_IMAGE_TX status 0` and `DONE_RESP 1`.

The preferred next test is host-side.  The programmer carries an outer
22-entry SHA-256 table at file `0x1028` (entry 0 = ELF-header hash, entry 1 =
zero for the hash segment itself, entries 2..21 = segment digests).  Entry 21
at file `0x12c8` is the SHA-256 of the programmer executable segment
(`p_filesz` exactly).

There is a second, nested table: phdr[21] is itself an ELF64 image (a
Qualcomm QTI-signed XBL_SEC component) with its own 6-entry hash table at
embedded `0x1b8`.  The one-byte modification is inside that embedded image's
phdr[5], so inner entry [5] is stale too.

Two host-side candidates are built and verified offline:

- `devprg_710_mod_hashfix2.bin` (`3845f397…398f`), the **double fix**:
  patches inner entry [5] at file `0x971d4` to `6ac567e4…22d9`, then
  recomputes the outer phdr[21] digest and patches outer entry 21 at
  `0x12c8` to `df94797b…38a1`;
- `devprg_710_mod_hashfix.bin` (`a1e1510e…f10e`), the **outer-only control**:
  patches only outer entry 21 to `fe58739b…112f`; inner entry [5] stays
  clean.

Both use the stock segment1.  The outer table is not self-checked and the
outer RSA-signature verifier sits behind a dead PKI gate, so the outer hash is
effectively unsigned in this path.  The inner XBL_SEC is QTI-signed; the
double fix satisfies its hash table but not its signature, and whether its
verifier runs is unknown.  Neither candidate has been tested on hardware.

Recomputing both tables from the bytes gives a clean 2x2 (outer entry 21 vs
the outer segment hash; inner entry [5] vs the inner phdr[5] hash):

| Image | Outer table | Inner table |
|---|---|---|
| signed `devprg_710` | OK | OK |
| `devprg_710_mod.bin` (DRM byte only) | stale | stale |
| `devprg_710_mod_hashfix.bin` | OK | stale |
| `devprg_710_mod_hashfix2.bin` | OK | OK |

The pristine image verifying on both tables is a positive control for the
digest model.  The one-byte `CRM`->`DRM` edit sits inside inner `phdr[5]`,
which is inside outer `phdr[21]`, so it broke both tables by itself.

A skip-BC4C candidate was built but is withdrawn: it zeroes
`0x1480fbb0+0xb8`, a fuse-derived secure-mode bit; that skips `0x31117c`
secure setup, and if `ctx+0x40` is zero the later `0xe58c` asserts/hangs.
It is not a safe fallback.

The RAM-only fallback is postflags v4: call the real `0x30b3b0`, set byte
`0x1480c378 = 1` (the DE40 success lever; `0x379`/`0x51` are the abort
bytes), then call `0x30de40` again.  It is relocation-safe because it uses
relative `ret` and absolute PBL/IMEM addresses.  It is built but untested.

### Firehose reset_to_edl

With the signed programmer running, `<data><power value="reset_to_edl"/>
</data>` returned `<response value="ACK" .../>` and the phone re-enumerated
as `05c6:9008`.  This provides a controlled EDL transition while a signed
programmer is running.  It does not recover a PBL already wedged in
`END_IMAGE_TX status 1`; that state still needs a power cycle.

## Separate auth and unlock research

No unsigned or modified programmer execution and no bootloader unlock have
been demonstrated. Two **different** modified-programmer observations must
not be merged:

- `W-PHASEC` (historical Windows `pblexp`, original phase payload):
  `devprg_710_mod.bin` was rejected with `END_IMAGE_TX image=0xd status=1`.
- `M-MOD-PF2` / `M-MOD-LT2` (native macOS, 2026-11-10): the same modified
  image served all 181 READ_DATA64 bytes, then the device reset before
  `END_IMAGE_TX`/`DONE_RESP`.

`M-MOD-LT2` used `segment1_loader_table_v2.bin`, whose resident stub was
malformed (`UDF`), so it is not a valid table-patch result. The full
experiment table is in [EVIDENCE.md](EVIDENCE.md).

Private firmware analysis recorded a status-1 return path near `0x308f34`
(the exact emitter was not re-verified in the latest pass), an early return
in `FUN_0030DE40` when finalize flags are unset, and a programmer auth
callback table at `0x14811620`, `0x14811658/60/68` that is **never read** in
this path (zero references; all-zero live IMEM). The loader-table
candidates (v1 `f488ee50…3148` wrong call target, v2 `2e7a9b2c…24b2d` UDF
constants, v3 `cc8f186c…8cb40b` valid instructions) are therefore inert.
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
