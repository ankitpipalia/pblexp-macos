# Independent verification — 2026-11-10

Verified the review of commit `f31a9d3` and the hardening commit `e663f16`.
No device discovery, USB operation, flashing, or storage command was performed
for this verification.

## Commands and results

Fresh public clone:

```bash
gh repo clone ankitpipalia/pblexp-macos /tmp/pblexp-public
cd /tmp/pblexp-public
python3 -m unittest discover -s tests -q
# Ran 64 tests ... OK

python3 pblexp_macos.py self-test
# SELF-TEST: PASS (offline; no device opened, mock host sequence)

python3 pblexp_macos.py ping --dry-run
# configure XML (ufs): 170 B
```

Also checked:

- `python3 -S -m unittest discover -s tests` — 64 tests OK with site
  packages disabled.
- `python3 -m py_compile pblexp_macos.py usb_edl.py tests/*.py` — OK.
- `git diff --check` — clean.
- Private-resource integration (outside the public checkout):
  `check-resources` and `dry-run --mode all` pass against the owned
  oppo710 resources and signed programmer; custom loader-table segment1
  hash check passes.
- Sample wire packets confirm the corrected layouts: READ_DATA64 total
  `0x20`, image `+0x08`, offset `+0x10`, size `+0x18`; END_IMAGE_TX total
  `0x10`, status `+0x0c`.

## Review findings

The 20 findings in the external review were checked against the hardening
diff and tests:

- packet-buffered USB reads with retained surplus: implemented;
- programmer/resource preflight before host I/O: implemented;
- one transport open per lifecycle: implemented;
- CDC request signature/opt-in: fixed and documented as experimental;
- disconnect classification and reconnect: implemented for tested
  transitions;
- strict host request validation: implemented;
- deadline, rejection and parser termination: implemented;
- one USB backend for bus/address selection and ZLP error propagation:
  implemented;
- bounded ranges, image IDs, custom-hash requirement, zero generation,
  ping dry-run, DONE status and numeric bounds: implemented and tested.

The Windows RE packet-offset corrections are reflected in
`WINDOWS-PBLEXP-RE.md`; the original shifted offsets are explicitly marked
as prior annotations.

## Remaining limits (initial offline verification)

These limits describe the state **before** the live runs recorded below.
The live sections supersede the hardware-unvalidated statement.

- **At the time of this offline verification, hardware behavior was
  unvalidated.** The first 48-byte Hello710 bulk-OUT timeout remained
  unexplained until the initial-HELLO drain fix.
- The review’s P1 receive-buffering and aligned-ZLP issues occur later and
  do not explain the first-write timeout.
- The signed-programmer Windows baseline and private payload hashes are
  historical records, not independently reproduced from the public repo.
- Loading a signed programmer does not establish an authentication bypass.
- No modified programmer, bootloader unlock, partition write, or RPMB write
  is demonstrated.

Verdict: the hardening commit addresses the reviewed host-side defects and
the public offline suite passes. It is suitable for another **cold-device**
live test, not for an unlock claim.


## Live native host validation (added after initial offline verification)

A cold EDL run with the hardening changes plus an additional **initial-HELLO
drain** completed the native host sequence on macOS:

```text
initial RX 0x30 B (drained before Hello710): 0100000030000000
TX hello710 / elf_header / program_headers / segment1 -> READ_DATA64
RX zero END_IMAGE_TX image=0xd status=0x8
175 reset HELLOs
segment2 + segment3
handoff -> USB bus=1 address=2 ports=(1,)
```

This validates the native macOS host half through segment3. It does **not**
validate the loader serve half: after handoff, the tool opened the new USB
address but sent LOADER_HELLO and received no Sahara packet
(`READ_DATA requests: 0`, read timeout). The loader-state transition remains
open. The initial-drain change is the reason the first Hello710 OUT no longer
times out; it was not part of the reviewed commit.


## End-to-end signed-programmer validation (live, 2026-11-10)

After adding the same unsolicited-HELLO drain to the loader-serve half, a
cold EDL run completed the full native sequence:

```text
host:
  initial RX 0x30 B HELLO drained: 0100000030000000
  TX hello710 / elf_header / program_headers / segment1 -> READ_DATA64
  RX zero END_IMAGE_TX image=0xd status=0x8
  175 reset HELLOs
  segment2 + segment3
  handoff -> USB bus=1 address=2 ports=(1,)

serve:
  initial loader RX 0x30 B HELLO drained before LOADER_HELLO
  READ_DATA requests: 181; bytes served: 0xa850c
  RX END_IMAGE_TX image=0xd status=0x0
  RX DONE_RESP: complete (status 1)
  RESULT: Sahara complete
```

The served image was the signed OEM `devprg_710` (SHA-256
`a9fc1744...6f214`). A subsequent Firehose read returned the programmer's
build banner (2019-03-04) and its supported-function list, and
`<power value="reset"/>` returned `<response value="ACK" .../>`. The device
then powered down/off; no Android or fastboot enumeration followed, so
recovery from that state still needs a physical power-on.

This validates the macOS host sequence, loader handoff, serve path, and
Firehose transport end-to-end. It does **not** validate the auth-bypass
payload or a modified programmer. The signed programmer is the control:
a normal loader accepts it without the exploit patch. The modified-programmer
and loader-table results are recorded in [EVIDENCE.md](EVIDENCE.md); the
corrected v3 table payload is not yet tested.

## Payload execution proof (live, 2026-11-10)

A direct-TX oracle payload at segment1 offset `0x970` proved execution:

```text
host: normal sequence through zero + 175 reset HELLOs + segment2/3
device -> host, immediately after segment2/3:
  PBLXORACLE2026!!EXEC-PROOF-0x9700123456789ABCDEF   (48 bytes)
```

The payload called the PBL TX primitive `0x308b40`; no code-pattern scan.
This is the first direct proof that the `0x970` slot executes on C.01 and
that it runs after segment2/3.

Corrected postflags and loader-table payloads use a PC-relative `bl #0x84`
to the stub at payload offset `0xb90`; the segment1 trampoline copies the
payload to `0x149ff000` and branches there, so the stub runs at
`0x149ff720`.  The earlier `0x85e28b90` absolute-target assumption was
wrong.  Signed `devprg_710` loads with the corrected postflags payload.

The first corrected loader-table stub was still malformed: it stored
`0x2ec88ff0` as a raw instruction word (UDF), not `movz/movk/ret`.  v3
writes valid instruction words, but the table it patches
(`0x14811620/58/60/68`) has zero references in the PBL and is all-zero in
live IMEM, so v3–v6 are inert.  Modified `devprg_710_mod.bin` still serves
all 181 READ_DATA64 requests (`0xa850c` bytes), then resets before
END_IMAGE_TX/DONE — with its stale hash table, the unpatched image is
rejected.  skip-BC4C is
withdrawn as hazardous.

**2026-11-11 recovery note.** During the VIP probe an `erase` command was
executed by the programmer (VIP turned out to be off) and formatted LUN 0.
The device was restored to C.01 from the OTA `system` image plus its own C.01
state dumps, with userdata formatted in recovery; it boots, adb works, and
`ro.boot.flash.locked` is still `1` / `verifiedbootstate` `green`. See
`docs/FIREHOSE-VIP.md`.

**2026-11-11 hardware result.**  The host-side hash-table fix works.  Both the
double fix (`devprg_710_mod_hashfix2.bin`) and the outer-only control
(`devprg_710_mod_hashfix.bin`) were accepted by the device: 181 READ_DATA64,
`END_IMAGE_TX (13,0)`, `DONE status 1` — identical to the signed control.
The unpatched image still fails (reset before END/DONE).  The outer-only
acceptance proves the embedded XBL_SEC's inner table is not enforced in this
path, so the outer 22-entry table (entry 21 at file `0x12c8`) is the only hash
gate.  This is a programmer-auth bypass, not an unlock: no write was made and
`flash.locked` stayed `1`.  Logs: `work/evidence-2026-11-11/` in the private
research tree.
