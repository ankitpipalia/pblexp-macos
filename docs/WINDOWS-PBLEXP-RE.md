# `pblexp.exe` (OPPOQcomPatchTool) — Windows RE for a native macOS port

Date: 2026-11-10
Scope: static reverse engineering of the shipped Windows tool. **No device was contacted, no
serial port was opened, and the original artifact was never modified.** All work was done on
copies in `/tmp`.
Companion data originally lived in `resources/RESOURCES-WINDOWS.json` and
extracted private resource files; those artifacts are not included in this public checkout.

**Review correction (2026-11-10):** This is an archival static-analysis record, not
a fresh independent reproduction. Resource hashes and disassembly claims require the
original binaries to verify. The HELLO payload bytes were not recovered statically.
Wire offsets and the DONE inference in §5.4–5.5 are corrected below; historical Python
comparisons in §8 describe predecessor scripts, not the current native CLI. Current
behavior and offline checks are in [IMPLEMENTATION-REVIEW.md](IMPLEMENTATION-REVIEW.md).

---

## 0. TL;DR

* The tool is a **32-bit x86 NativeAOT (.NET 8/9-style) console app**, shipped **UPX-packed**.
  `upx -d` reproduces the provided "unpacked" file bit-for-bit (same SHA-256), so the supplied
  artifact *is* the faithful UPX decompression.
* It embeds **11 managed resources** in one contiguous, unpadded `.rdata` blob
  (`0x11c0d2..0x120d6a`, total `0x4c98`). All 11 were extracted and hashed; the five files the
  team already had (`segment1/2/3.bin`, `oppo710_elf_header.bin`, `oppo710_program_headers.bin`)
  match the artifact **byte-for-byte**.
* Serial configuration is **115200 baud, 8 data bits, parity None, 1 stop bit, no handshake,
  DTR and RTS never touched, ReadTimeout = WriteTimeout = 10000 ms**.
* `-m oppo710` runs a fixed 8-step write sequence with a **175-iteration `0x13`/`0x30` loop**,
  then **closes the port, sleeps 1000 ms, reopens it**, sends a second 0x30-byte "loader Hello"
  and then acts as a **Sahara host serving the programmer file from disk** (`READ_DATA64`,
  `END_IMAGE_TX`).
* Biggest surprise for the port: the hello/handshake **payload bytes are not present in this
  artifact** — they live in zero-initialised `.data` (see §7.1). Lengths, ordering and framing are
  fully recovered; the actual 0x30-byte values must come from the live capture.
* Biggest surprise in behaviour: the two SoC paths differ structurally. `oppo845` sends an extra
  `0xb98`-byte all-zero block and uses a **16-byte** reset packet; `oppo710` sends only the
  `0xbf8` zero block and a **1-byte** `0x13` reset packet. `oppo665` is a completely different,
  exploit-free flow.

---

## 1. Artifacts and method

| Artifact | Path | SHA-256 | Size |
|---|---|---|---|
| Packed original (UPX) | `rmx1901-artifacts/win-tools/pblexp.exe` | `f9accd904066393699105ab1c6c783ad7b934b703df12cb2ad80e3c767945eb6` | 799,744 |
| Unpacked = UPX output | `work/pblexp-oppo710/pblexp_unpacked.exe` | `a6fa5d6f94c9513540c98f5c418ac5a2c7b8f1ccfaf919376b843446b12b837f` | 1,805,312 |

Verification of the packing claim:

```
$ upx -d -o /tmp/pblexp_upx/pblexp_upx.exe /tmp/pblexp_upx/orig.exe
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   1805312 <-    799744   44.30%    win32/pe     pblexp_upx.exe
$ shasum -a 256 /tmp/pblexp_upx/pblexp_upx.exe
a6fa5d6f94c9513540c98f5c418ac5a2c7b8f1ccfaf919376b843446b12b837f
```

Tools used: `pefile 2024.8.26`, `capstone 5.0.7`, `rizin`, `upx`, Python. `dnfile`/`monodis` are
not applicable (no CLI metadata — see §2). Ghidra 12.1.4 was available but its MCP decompiler
calls timed out at the client; all results below come from linear/flow-following x86 disassembly
plus data-structure parsing, cross-checked structurally.

The Windows host copy `C:\<pbl-host>\pblexp.exe` was **not
reachable** from this macOS session; it is only relevant if its hash differs from the packed
original above (worth confirming on the Windows side — see §9).

---

## 2. PE / managed structure

```
Machine            0x014c (IMAGE_FILE_MACHINE_I386), PE32, Subsystem 3 (console)
Characteristics    0x0102 (EXECUTABLE_IMAGE | 32BIT_MACHINE)
TimeDateStamp      1790489496  ->  2026-09-27T06:11:36Z
ImageBase          0x00400000
EntryPoint         0x00f28d9 (VA 0x4f28d9)
SizeOfImage        0x00202000
```

| Section | VA | VirtualSize | RawPtr | RawSize |
|---|---|---|---|---|
| `.text` | `0x401000` | `0xf58a6` | `0x400` | `0xf5a00` |
| `.rdata` | `0x4f7000` | `0xa5df4` | `0xf5e00` | `0xa5e00` |
| `.data` | `0x59d000` | `0x47800` | `0x19bc00` | **`0x1400`** |
| `.pdata` | `0x5e5000` | `0x1197c` | `0x19d000` | `0x11a00` |
| `.rsrc` | `0x5f7000` | `0x5c6` | `0x1aea00` | `0x600` |
| `.reloc` | `0x5f8000` | `0x9b38` | `0x1af000` | `0x9c00` |

* **No `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`** — there is no CLI header and no IL. Imports are
  the NativeAOT runtime surface only: `KERNEL32.DLL` (142), `ADVAPI32.dll` (10),
  `api-ms-win-crt-*` (35 total), `bcrypt.dll` (1), `ole32.dll` (4). No `mscoree.dll`.
* **NativeAOT metadata survives**: method-name strings such as `SendLoader`, `ReadPacket`,
  `PrintUsage`, and the full `System.Private.CoreLib` / `System.IO.Ports` type surface are in
  `.rdata`. The `System.IO.Ports.SerialPort` and `SerialStream` implementations are compiled into
  the image, so serial semantics are the Windows .NET implementation, not Win32 directly.
* Version resource (`.rsrc`, RT_VERSION):

```
CompanyName       OPPOQcomPatchTool
FileDescription   OPPOQcomPatchTool
FileVersion       1.0.0.0
InternalName      OPPOQcomPatchTool.dll
OriginalFilename  OPPOQcomPatchTool.dll
ProductName       OPPOQcomPatchTool
ProductVersion    1.0.0+build20260927061130Z
Assembly Version  1.0.0.0
```

* There is also a `RT_MANIFEST` (type 24) alongside RT_VERSION; `.rsrc` contains **no** RCDATA
  payload — the managed resources are *not* Win32 resources (§3).
* **`.data` is 0x1400 raw of 0x47800 virtual.** This is load-bearing for the port; see §7.1.

---

## 3. Embedded managed resources

### 3.1 How they are stored

The resources are one contiguous, unpadded blob in `.rdata`. The manifest names sit immediately
after the blob (`0x120d8e` onwards) as a NativeAOT resource manifest of
`"OPPOQcomPatchTool, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"` +
`"OPPOLoaderTest.Resources.<file>"` pairs.

The blob start and every boundary were established **independently** of the manifest:

* `common_zero_segment` is the run of exactly `0xbf8` zero bytes ending precisely at the first
  ELF header (`0x11c0d2 + 0xbf8 = 0x11ccca`).
* Each subsequent boundary is the previous `offset + size`, and the sizes are self-checking:
  `oppo710_elf_header.e_phnum = 22` × 56 = `0x4d0` = `oppo710_program_headers` size;
  `oppo845_elf_header.e_phnum = 19` × 56 = `0x428` = `oppo845_program_headers` size
  (both `e_phentsize = 56`, `e_phoff = 0x40`, `e_machine = 0xb7` = AArch64, `EI_CLASS = 2`).
* The sum of all 11 sizes equals the distance to the manifest start (`0x4c98`), with **no
  padding anywhere**.
* The tool's own resource table (built at `0x4040f9..0x4041c4`) lists the same 11 lengths in the
  same order: `0xbf8, 0x40, 0x4d0, 0x1000, 0x3f0, 0x3a8, 0x40, 0x428, 0x1000, 0xb98, 0x3f8`.

The manifest lists exactly these 11 resources, and the code's resource table has exactly 11
entries, in the same order.

### 3.2 Extracted resources

All extracted to `work/macos-port/resources/`; machine-readable copy in
`resources/RESOURCES-WINDOWS.json`.

| # | Resource name | File offset | Size | SHA-256 | Non-zero bytes |
|---|---|---|---|---|---|
| 1 | `common_zero_segment.bin` | `0x11c0d2` | `0xbf8` | `cb9d8ad98a67bce84c7726b113d37ba7b9a48a87431c0ad9422ffbbb85da4e51` | 0 (all zero) |
| 2 | `oppo710_elf_header.bin` | `0x11ccca` | `0x40` | `8b0783b70f4793cdddbce64d51775ec1b261a65968ef3087bd44aa046360ba4a` | 18 |
| 3 | `oppo710_program_headers.bin` | `0x11cd0a` | `0x4d0` | `fbb4b23984616972b225c48298a9f82d8d39c76b0ca304e066c095be28ead42e` | 352 |
| 4 | `oppo710_segment1.bin` | `0x11d1da` | `0x1000` | `da6cffd174d8bac3d56b7b024ff35cca6d393368f7de7a719ea3e0f2bff58b5b` | 460 |
| 5 | `oppo710_segment2.bin` | `0x11e1da` | `0x3f0` | `26712a9af552ca20a9594ab0f6eb96427b302388a47f7f8672c6b002fa36aa3a` | 4 |
| 6 | `oppo710_segment3.bin` | `0x11e5ca` | `0x3a8` | `d68e5c4385f289c59469c0567718a4b127a56321cf3bb722298c58814d312692` | 18 |
| 7 | `oppo845_elf_header.bin` | `0x11e972` | `0x40` | `d83626e8efa328501b6fd258dc02f4df9ab25bbedd5978bcfc708df707e3ee30` | 18 |
| 8 | `oppo845_program_headers.bin` | `0x11e9b2` | `0x428` | `518de93622a1d31c04f959f320d519f0c5cfcea6022d517941c3b3e40373e8e8` | 295 |
| 9 | `oppo845_segment1.bin` | `0x11edda` | `0x1000` | `2f508338dc929071b8e9be876e9167de8a7ed86c15a2dd65b6fcdf1514033f76` | 459 |
| 10 | `oppo845_segment2.bin` | `0x11fdda` | `0xb98` | `4fe273f1e9efb9d6b4ed4b2c760b2bb6741e6d532b4583a37a91787986db6a62` | 0 (all zero) |
| 11 | `oppo845_segment3.bin` | `0x120972` | `0x3f8` | `db72db098dd7c5666fc7c469c7ca7d01bb8e30e746d6d3353cf4cacab432d1e4` | 28 |

Blob extent: `0x11c0d2 .. 0x120d6a` (`0x4c98` bytes). Manifest strings start at `0x120d8e`.

### 3.3 Comparison with the local known files

| Local file | Bytes | SHA-256 | vs artifact |
|---|---|---|---|
| `work/pblexp-oppo710/oppo710_elf_header.bin` | 64 | `8b07…ba4a` | **MATCH** |
| `work/pblexp-oppo710/oppo710_program_headers.bin` | 1232 | `fbb4…42e` | **MATCH** |
| `work/pblexp-oppo710/segment1.bin` | 4096 | `da6c…8b5b` | **MATCH** |
| `work/pblexp-oppo710/segment2.bin` | 1008 | `2671…aa3a` | **MATCH** |
| `work/pblexp-oppo710/segment3.bin` | 936 | `d68e…2692` | **MATCH** |

No mismatches. The previously reported `common_zero_segment.bin` extraction **was wrong**:
the real resource is the all-zero `0xbf8` block at `0x11c0d2` (SHA-256 `cb9d…4e51`), not a
non-zero `.NET` manifest fragment. `pbl_host_magic.py` already regenerates the zero block and
documents this; that workaround is now confirmed by the artifact and can be simplified to a file
load or a `b"\0" * 0xbf8` constant.

Also cross-checked: the sibling port agent's `resources/segment1.bin`,
`resources/segment2.bin`, `resources/segment3.bin`, `resources/oppo710_*` all match these hashes.

---

## 4. Serial parameters

Established from the port initialiser at `0x403570` (called by every `Run*` entry and by
`SendLoader`). `ecx = port name`.

```asm
0x403570  ; SerialPort SerialInit(string portName)
0x403579  mov  ecx, 0x5bc9bc        ; (type/strings for port name)
0x403585  call 0x4047a4             ; Console.Write("尝试打开端口: " + portName)
0x40358a  mov  ecx, 0x5c066c
0x40358f  call 0x4bf35e             ; new SerialPort()          -> edi
0x403596  call 0x4063fc             ; ctor
0x40359d  mov  edx, esi
0x4035a1  call 0x406238             ; set_PortName(portName)     [string setter]
0x4035a8  mov  edx, 0x1c200
0x4035ad  call 0x4060a4             ; set_BaudRate(0x1c200)
0x4035b4  xor  edx, edx
0x4035b6  call 0x4061dc             ; set_Parity(0)
0x4035bd  mov  edx, 8
0x4035c2  call 0x40614c             ; set_DataBits(8)
0x4035c9  mov  edx, 1
0x4035ce  call 0x40633c             ; set_StopBits(1)
0x4035d5  mov  edx, 0x2710
0x4035da  call 0x4062dc             ; set_ReadTimeout(10000)
0x4035e1  mov  edx, 0x2710
0x4035e6  call 0x40639c             ; set_WriteTimeout(10000)
0x4035ed  call 0x4065e8             ; Open()
0x4035f2  ret
```

Setter identity was corroborated by their internal validation constants:
`0x4061dc` rejects parity > 4, `0x40614c` uses the 5..8 data-bits range, `0x40633c` rejects
stop-bits > 2, `0x4062dc` validates `>= -1`.

| Parameter | Value | Evidence |
|---|---|---|
| Port name | from `-p`, used verbatim (`COM3`, …) | `0x40359d` |
| Baud rate | **115200** | `0x4035a8` (`0x1c200`) |
| Data bits | **8** | `0x4035bd` |
| Parity | **None** (enum 0) | `0x4035b4` |
| Stop bits | **One** (enum 1) | `0x4035c9` |
| Handshake | **not set** → .NET default `Handshake.None` | no setter call anywhere |
| DTR | **not set** → `DtrEnable = false` | `DtrEnable` appears only as a metadata name (`0x106157`); no call site |
| RTS | **not set** → `RtsEnable = false` | `RtsEnable` appears only as a metadata name and as an exception message (`0x14b364`) |
| ReadTimeout | **10000 ms** | `0x4035d5` |
| WriteTimeout | **10000 ms** | `0x4035e1` |
| Encoding | not set → .NET default ASCII for `Write(string)`; **the tool writes `byte[]`, so encoding is irrelevant** | `0x403d38` |
| DiscardNull / threshold / etc. | not set | — |

Reads are `SerialPort.Read` loops (helper `0x403e80`) bounded by the 10 s `ReadTimeout`; a short
read therefore raises `TimeoutException` and aborts the run. Writes go through
`port.BaseStream.Write(byte[], 0, byte[].Length)` (`0x403d38`), so **the write timeout governs
the whole transfer**.

The artifact shows no DTR/RTS setters. That says nothing about the Qualcomm vendor
driver's USB control traffic. Native macOS bulk USB has no tty modem-control layer;
the current port sends no CDC setup requests by default. `--usb-cdc` is an experimental
opt-in pending a Windows USB capture, not established `usbser.sys` compatibility.

---

## 5. `oppo710` command sequence

### 5.1 Dispatch

`Main` parses `-p/-m/-f`, then dispatches by model string (`0x4028a5`, `0x4028c3`, `0x4028e1`):

| Model | Function | Identification evidence |
|---|---|---|
| `oppo665` | `0x4032e0` | only path with the "no initial Hello / 100 attempts" logic; no `oppo710/845` resource references |
| `oppo710` | `0x402e60` (`Run710`) | loads `oppo710_*` resources; 1-byte `0x13` × 175 loop |
| `oppo845` | `0x4030a0` (`Run845`) | loads `oppo845_*` resources; 16-byte reset packet |

`Run710(portName, filePath)` — full body `0x402e60..0x403019`.

### 5.2 Exact sequence (oppo710)

Every "write" is one `SerialPort.BaseStream.Write`; every "read" is a `ReadExactly(n)`.

| # | Action | Bytes written | Source | Read |
|---|---|---|---|---|
| 1 | Hello 710 | **0x30** | `Packets[+0x08]` (0x60-byte UTF-16 blob converted at startup) | **0x20** |
| 2 | ELF header | **0x40** | `oppo710_elf_header.bin` | **0x20** |
| 3 | Program headers | **0x4d0** | `oppo710_program_headers.bin` | **0x20** |
| 4 | Segment 1 | **0x1000** | `oppo710_segment1.bin` (exploit payload at `+0x970`) | **0x20** |
| 5 | Zero segment | **0xbf8** | `common_zero_segment.bin` (all zero) | **0x10** |
| 6 | Reset/spray loop ×**175** | **1** (`0x13`) each | `Packets[+0x14]` | **0x30** each |
| 7 | Segment 2 | **0x3f0** | `oppo710_segment2.bin` | **none** |
| 8 | Segment 3 | **0x3a8** | `oppo710_segment3.bin` | **none** |
| 9 | — | — | `port.Dispose()` | — |
| 10 | — | — | `Thread.Sleep(1000)` | — |
| 11 | Loader Hello | **0x30** | `Packets[+0x04]` (different 0x60-byte UTF-16 blob) | (serve loop) |
| 12 | Sahara serve | see §5.4 | programmer file from `-f` | per request |

Totals for the `Run710` phase: **10,623 bytes written**, **8,544 bytes read**
(4×0x20 + 0x10 + 175×0x30). The 175 count is the literal `0xaf` at `0x402f39`
(`mov dword [ebp-0x10], 0xaf`), so **175 is confirmed**, not approximate.

Key instruction sites:

```
0x402e9d  mov edx,[ebx+0x08]      ; Hello710
0x402eab  mov edx,0x20            ; read 0x20
0x402f18  mov ecx,0x5ba8d4        ; zero segment (lazy resource load)
0x402f2f  mov edx,0x10            ; read 0x10
0x402f39  mov dword [ebp-0x10],0xaf
0x402f40  mov edx,[ebx+0x14]      ; 1-byte 0x13
0x402f4e  mov edx,0x30            ; read 0x30
0x402f61  mov ecx,0x5bb904        ; segment2
0x402f75  mov ecx,0x5bb934        ; segment3
0x402ff7  mov ecx,[ebp-0x14]; call 0x40d600   ; Dispose
0x402fff  mov ecx,0x3e8; call 0x433638        ; Thread.Sleep(1000)
0x40300d  call 0x4035f8                       ; SendLoader
```

`Packets` is the static object at `[0x59d44c]`, built by the type initialiser at
`0x40401c..0x4041c4`. Its six pre-sequence slots are, in order:
`+0x04` 0x60-byte blob, `+0x08` 0x60-byte blob, `+0x0c` 0x10 bytes, `+0x10` 4 bytes
(`13 9a 9a 9a`), `+0x14` 1 byte (`0x13`), `+0x18` 0x10 bytes.

### 5.3 `Run845` and `Run665` (for comparison)

`Run845` (`0x4030a0..0x403266`):

| # | Action | Bytes | Read |
|---|---|---|---|
| 1 | Hello (same `Packets[+0x04]` blob used by SendLoader) | 0x30 | 0x20 |
| 2 | `oppo845_elf_header` | 0x40 | 0x20 |
| 3 | `oppo845_program_headers` | 0x428 | 0x20 |
| 4 | `oppo845_segment1` | 0x1000 | 0x20 |
| 5 | `oppo845_segment2` (all-zero resource) | 0xb98 | 0x10 |
| 6 | `common_zero_segment` | 0xbf8 | 0x10 |
| 7 | reset loop ×175, `Packets[+0x18]` | **0x10** each | 0x30 each |
| 8 | `oppo845_segment3` | 0x3f8 | none |
| 9 | dispose, `Sleep(1000)`, `SendLoader` | — | — |

So `oppo845` sends **two** zero blocks (the 0xb98 resource *and* the 0xbf8 resource) and uses a
16-byte spray packet; `oppo710` sends only the 0xbf8 block and a 1-byte `0x13` packet. The
`0x4038xx` branch of the serve routine and the different hello slot mean the two SoCs are not
interchangeable.

`Run665` (`0x4032e0`) is a different protocol entirely — it opens the port, calls `ReadPacket`
(`0x403ec4`) in a loop waiting for the device's initial Hello (up to **100** attempts, per the
literal `oppo665 在 100 次尝试后仍未进入引导传输阶段。`), then hands the already-read packet to
the same serve routine `0x403720`. No image upload, no 175 loop, no close/reopen.

### 5.4 `SendLoader` and the Sahara serve loop

`SendLoader(portName, filePath)` (`0x4035f8..0x4036ba`):

1. `SerialInit(portName)` — **a brand-new `SerialPort` and `Open()`**, i.e. the port really is
   closed and reopened after the 1 s sleep.
2. Write `Packets[+0x04]` (0x30 bytes) — the loader Hello.
3. `ServeFile(port, filePath, firstPacket = 0)` (`0x403720`).

`ServeFile` (`0x403720..0x403c3b`) opens the programmer file with
`new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 0x1000,
options: 0)` and then loops:

* `pkt = ReadPacket(port)`
* `cmd = u32 at pkt[0]`, `len = u32 at pkt[4]` (total length including the 8-byte header)
* **`cmd == 0x04` (`END_IMAGE_TX`)**: standard wire length is `0x10`; image is
  u32 at byte `+0x08`, status u32 at byte `+0x0c`. The prior `pkt[0x14]`
  annotation was not a valid wire offset.
  * `status != 0` → builds `"ImageTxStatus:" + status` and reports failure (`0x403952`)
  * `status == 0` → writes `Packets[+0x0c]` (**0x10 bytes**), does one more `ReadPacket`,
    prints, and returns (`0x40384c..0x40386d`)
* **`cmd == 0x12` (`READ_DATA64`)**: standard wire length is `0x20`; image is
  u64 at byte `+0x08`, offset u64 at `+0x10`, size u64 at `+0x18`. The prior
  `len >= 0x28`, `+0x18` / `+0x20` annotations were shifted by eight bytes
  relative to the wire. The recorded implementation validates the request against the
  stream, repositions the file, reads `length` bytes and **writes them to the port with no
  additional header** (`0x40378b..0x4037d4`). The loop then continues.
* **anything else** → prints `收到意外的 Sahara 命令: <cmd>` and aborts (`0x403b77`).

`ReadPacket` (`0x403ec4`) framing:

```
read exactly 8 bytes           -> header
len = u32(header+4)
if len < 8 or len > 0x1000     -> error ("报文长度不足" / length checks at 0x403ef7, 0x403f19)
buf = new byte[len]; copy header; if len > 8 read exactly len-8 more
```

`ReadExactly` (`0x403e80`) loops on `SerialPort.Read` until `n` bytes are collected; the 10 s
`ReadTimeout` applies per underlying read.

### 5.5 DONE and Firehose: limits of the static evidence

The absence of an incoming `0x05` DONE handler does **not** establish that this host
sends no DONE: hosts send DONE and receive DONE_RESP. Standard DONE is an 8-byte
host packet; DONE_RESP is 12 bytes with u32 status at byte `+0x08` (`0` pending,
`1` complete). See [qdl's Sahara implementation](https://github.com/linux-msm/qdl/blob/master/src/sahara.c).

The recorded post-END_IMAGE success path writes `Packets[+0x0c]`, annotated as
`0x10` bytes, then reads another packet. That annotation alone cannot identify the
payload as standard DONE. Re-examine its actual bytes, managed-array lengths, and
a sanitized Windows capture before claiming whether it sends DONE or uses a quirk.
The earlier conclusion that the artifact deliberately implements no DONE is withdrawn.

The original analysis found no host Firehose XML literals in `.text` / `.rdata`
(`<?xml`, `<data`, `<response`, `configure`, `firehose`, `program`, `erase`;
the XML manifest was in `.rsrc`). This supports the narrower conclusion that no
literal XML configure path was found; it does not reconstruct all runtime traffic.
The current Python CLI separately implements an optional configure ping.

**Offset interpretation:** the old END_IMAGE and READ_DATA64 annotations may have
mixed a managed-array object's data offset with byte-array indexes. That is a
hypothesis requiring the original binary, not a confirmed explanation. On-wire
packet layouts above take precedence for the port.

---

## 6. CLI and overall flow

Usage literal (UTF-16 at `.rdata` file `0x15475c`):

```
用法: OPPOQcomPatchTool -p COM数字 -m oppo665|oppo710|oppo845 -f <引导文件路径>
```

(ASCII rendering: `OPPOQcomPatchTool -p COMx -m oppo665|oppo710|oppo845 -f <programmer>`.)

| Argument | Handling | Error literal |
|---|---|---|
| `--help` | prints banner + usage, exits | — |
| `--check-resource` | resource self-test, exits | `资源检查失败: ` |
| `-p <COMx>` | must be `COM` + positive integer | `-p 必须是 COM 后接正整数，例如 COM3。` |
| `-m <model>` | one of `oppo665`/`oppo710`/`oppo845` | `-m 必须是 oppo665、oppo710 或 oppo845。` |
| `-f <path>` | programmer file, must exist | `-f 必须指定引导文件。` / `引导文件不存在: ` |
| unknown/duplicate | abort | `未知或重复的参数: ` |

Flow in `Main` (`0x402560..0x40292x`):

1. Print banner (`# OPPO Qcom Patch Tool …`, `# 本程序可离线使用 (永久离线免费)`,
   `# 本项目仅供学习交流，请注意你的行为！`, `# 构建日期:`), or run the special modes.
2. `ParseArgs` (`0x4029a0`): tokenises `args[1..]`; compares the two-character switches as
   UTF-16 (`cmp dword [eax+8], 0x70002d` = `"-p"`, `0x6d002d` = `"-m"`, `0x66002d` = `"-f"`).
3. `--check-resource` path (`0x40262c..0x4026f1`): walks the 11-entry `{byte[] field, expected
   length}` table at `Packets[+0x1c]`, calls the lazy loader (`0x403c50`), compares
   `res.Length` with the expected size, and prints a per-resource OK/FAIL line. This is a
   ready-made oracle for the macOS port's resource table.
4. `File.Exists(file)` check, then dispatch on model (§5.1).
5. Print `引导发送成功` on success.

Resource loading: `LoadResource(fieldAddr)` at `0x403c50` takes the address of a static
"field" slot, resolves the resource by name, caches the `byte[]` in that slot and returns it.
All 11 image resources are loaded lazily through this one function.

`Main` returns `2` on argument/validation failure and `0` on the success path.

---

## 7. Surprises and discrepancies

### 7.1 The hello/handshake payloads are **not recoverable from this artifact**

The two 0x60-byte pre-sequence blobs are statically constructed at startup
(`0x40404d`, `0x40406b`, `0x404089`, `0x4040e2` call `0x4171e4`, which converts a UTF-16 buffer
of `n` bytes into an `n/2`-byte array; `n = 0x60` → **0x30-byte packet**).

Their sources are the fixed addresses `0x5a8ad0`, `0x5a8ba0`, `0x5a8c70`, `0x5a8cc4` (plus two
inline literals, `13 9a 9a 9a` and `13`) —
all inside `.data`'s **zero-initialised** region (`.data` raw is only 0x1400 of 0x47800).
The same is true of the model-name statics (`0x5bb768`, `0x5bb848`) and of the 12th
`Packets` slots. A byte scan of the whole image finds no UTF-16 copy of a 0x30-byte hello
packet, and the packed original decompresses to exactly this file, so this is not an artefact of
the unpacking step.

Consequences:

* **Sequence, sizes (0x30), ordering and framing are proven.** The team's captured `HELLO710`
  and `LOADER_HELLO` are both 0x30 bytes, which matches exactly.
* **The 0x30 byte values cannot be confirmed from this file.** For the macOS port, keep the
  live-captured bytes; do not attempt to regenerate them from the EXE.
* A related caveat: this also means the supplied EXE, as a *runnable image*, would start with
  those statics zeroed. Either the vendor build is normally accompanied by a different `.data`
  layout, or this copy was repacked from a partial dump. Treat the file as authoritative for
  **code, resources and structure**, not for BSS-resident constants.

### 7.2 Other findings

1. **The port is closed and reopened, not merely delayed.** `Sleep(1000)` is followed by a fresh
   `SerialPort` + `Open()` inside `SendLoader`. Any buffered RX is lost at that point.
2. **`oppo710` reads 0x10 after the zero segment**, not 0x20 (all four preceding reads are 0x20).
3. **`segment2`/`segment3` are written after the 175-reset loop with no reads in between** — i.e.
   they are part of the same "image transfer" but not acknowledged individually.
4. **`oppo845` uses a 16-byte reset packet and sends two zero blocks** (§5.3). A port that
   assumes one shared code path for 710/845 will mis-frame 845.
5. **The tool is a full Sahara host**: it does not merely push a file; it parses
   `READ_DATA64`/`END_IMAGE_TX`, serves arbitrary offsets/lengths from the programmer file, and
   reports `ImageTxStatus`. The predecessor scripts described in §8 stopped before this
   stage; the current `pblexp_macos.py` implements serving and completion checks.
6. **`--check-resource` exists** and validates all 11 embedded resources against expected sizes.
7. **No DTR/RTS/handshake configuration at all** — the only serial setup is baud/parity/bits/
   stop/timeouts (§4).
8. `oppo665` is exploit-free and semantically different from 710/845 (§5.3).
9. `common_zero_segment` really is `0xbf8` **zero** bytes; the earlier non-zero extraction was a
   manifest-fragment mistake (now corrected in §3.2).

---

## 8. Historical comparison with predecessor Python scripts

Archival comparison against `work/pblexp-oppo710/pbl_host_magic.py`,
`pbl_loader_probe.py`, `pbl_firehose_ping.py`. These are not the current
`pblexp_macos.py`; the gaps below describe that earlier state.

| Aspect | `pblexp.exe` (artifact) | Our Python | Verdict |
|---|---|---|---|
| First 4 writes + reads | hello 0x30/0x40/0x4d0/0x1000, each followed by read 0x20 | same order, read 0x20 each | **matches** |
| Zero segment | 0xbf8 all-zero resource, then read **0x10** | 0xbf8 default, "read variable" | read length now exact: **0x10** |
| Reset loop | 175 × (write 1 byte `0x13`, read 0x30) | same | **matches** |
| Post-loop | segment2 0x3f0, segment3 0x3a8, no reads | same | **matches** |
| After segment3 | `Dispose()`, `Sleep(1000)`, **new SerialPort**, write 0x30 loader hello, Sahara serve | keeps port open, raw read | **deliberate deviation** (documented in `pbl_host_magic.py`); now precisely characterised |
| Programmer upload | `READ_DATA64` serve loop from `-f` file + `END_IMAGE_TX` status parsing | not implemented | **gap to close for a full port** |
| `oppo845` | 0xb98 zero block + 0xbf8 zero block + 16-byte reset | not modelled | **gap** |
| `oppo665` | Hello wait (100 tries) then serve | not modelled | **gap** |
| Serial config | 115200 8N1, no handshake, 10 s timeouts | pyserial defaults (8N1 115200) | matches except DTR/RTS/timeout explicitness |
| Hello payload bytes | 0x30, content not in artifact | live-captured 0x30 | consistent; keep captured bytes |

Note on the "keep the port open" deviation: the artifact shows the close/reopen is *followed by*
a 0x30-byte loader Hello and a Sahara serve loop. If the exploit stage leaves a magic packet
pending, reopening discards it — consistent with the observed loss. A macOS port should keep
both modes: `pblexp-compatible` (close/reopen, then Hello+serve) and `raw-read` (the current
Python behaviour) for experimentation.

---

## 9. Original port checklist (archival)

1. **Resources**: the Windows artifact embeds 11 resources, but this public `oppo710`
   port needs only the subset listed in [../resources/README.md](../resources/README.md).
   Do not redistribute private binaries. `common_zero_segment` may be generated as
   `b"\0" * 0xbf8` and verified against its recorded hash.
2. **Transport**: native macOS uses direct bulk USB with maxpacket-multiple receive
   buffers and a retained logical-read queue. Preserve serial framing/settings only for
   an actual serial backend. Windows serial constants do not imply native CDC requests.
3. **Open/close/open**: implement the `Dispose → sleep 1000 ms → open` transition, and reset
   buffers on both opens.
4. **Sequence engine**: table-driven, per SoC, with the exact write/read sizes from §5.2/§5.3.
   175 is a literal, not a heuristic.
5. **Sahara host**: 8-byte header framing (`cmd`, `len`, max 0x1000), `READ_DATA64` file serve
   (offset/length 64-bit), `END_IMAGE_TX` status handling, `ImageTxStatus` reporting.
6. **Modes**: `check-resources` checks the current port's private resource subset; public
   `self-test` and unittest cases use synthetic fixtures without those resources.
7. **Do not** try to synthesise the hello payloads from the EXE (§7.1).

---

## 10. Evidence map

| Topic | Addresses / offsets |
|---|---|
| Serial init | `0x403570–0x4035f7` |
| `Run710` | `0x402e60–0x403019` (caller `0x4028c3`) |
| `Run845` | `0x4030a0–0x403266` (caller `0x4028e1`) |
| `Run665` | `0x4032e0–0x4034xx` (caller `0x4028a5`) |
| `SendLoader` | `0x4035f8–0x4036ba` (called from `0x40300d`, `0x40325a`) |
| Sahara serve | `0x403720–0x403c3b` |
| `ReadPacket` / `ReadExactly` / `Write` | `0x403ec4` / `0x403e80` / `0x403d38` |
| Lazy resource loader | `0x403c50` |
| `Packets` cctor | `0x40401c–0x4041c4` (guard `0x5be578`) |
| `--check-resource` loop | `0x40262c–0x4026f1` |
| `ParseArgs` | `0x4029a0` |
| Usage string | `.rdata` file `0x15475c` (VA `0x55595c`) |
| Banner strings | `.rdata` file `0x1413b0`, `0x1413e3`, `0x141410`, `0x14143f` |
| Resource blob | `0x11c0d2–0x120d6a` |
| Resource manifest | `0x120d8e–0x1212e1` |

### Confidence

* **Observed (high confidence)**: PE layout, section sizes, UPX provenance, resource offsets /
  sizes / hashes / names, serial constants, write/read sizes and ordering, 175 loop, 1000 ms
  sleep + reopen, packet framing, `READ_DATA64`/`END_IMAGE_TX` handling, CLI literals.
* **Inferred (medium)**: exact `SerialPort` property→setter mapping (from call order plus each
  setter's validation constant); interpretation of managed-object accesses versus wire
  offsets (see §5.4–5.5 corrections); model→function mapping for `oppo665` (by elimination plus the
  665-specific messages).
* **Unknown**: the two 0x30-byte hello payload values (§7.1); whether the Windows host copy at
  `C:\...\pbl-host\pblexp.exe` matches the packed original's hash; whether `ReadExactly` retries
  after a timeout; exact 0x665 Hello validation rules.
