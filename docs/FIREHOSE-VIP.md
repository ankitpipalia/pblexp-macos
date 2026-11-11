# Firehose / VIP authorization in the accepted programmer

Static analysis of the programmer image that the C.01 PBL accepts, performed
offline after the hash-table bypass was confirmed on hardware (2026-11-11).
No device interaction, no partition write. The programmer itself is not
redistributed here.

## Where Firehose lives

The Firehose server is the **main program** (program header 2, RX, entry
`0x1484aa40`), not the embedded XBL_SEC component. The command names, the
dispatch table and all handlers are in that segment.

## Command dispatch table

16 entries of `{char *name; void *handler}` at virtual address `0x1489b428`:

| # | Command | # | Command |
|---:|---|---:|---|
| 0 | `program` | 8 | `firmwarewrite` |
| 1 | `read` | 9 | `getstorageinfo` |
| 2 | `nop` | 10 | `benchmark` |
| 3 | `patch` | 11 | `emmc` |
| 4 | `configure` | 12 | `ufs` |
| 5 | `setbootablestoragedrive` | 13 | `fixgpt` |
| 6 | `erase` | 14 | `getvar` |
| 7 | `power` | 15 | `dump` |

`ufs` and `fixgpt` share a handler. `setbootablestoragedrive` is a
Motorola-specific addition; the image is Motorola OEM-signed.

## VIP is decided in EL3

The programmer does not decide whether VIP applies. Its predicate calls SCM
function `0x82000119` through the image's **single** `smc #0` instruction and
uses the returned value. The dispatcher then behaves differently:

- VIP off: dispatch directly.
- VIP on: only nine commands are allowed — `program`, `read`, `nop`,
  `configure`, `setbootablestoragedrive`, `power`, `getstorageinfo`, `getvar`,
  `dump`. Everything else logs `handler %s is restricted!` and fails.

`program` is additionally checked against a 17-entry
`{lun, start, length}` table, and each received packet is hashed against a
host-supplied signed digest table (`VIP hash table accepted %d packet %d`).

## The whitelist excludes the unlock-relevant partitions

Mapping the 17 ranges onto the device's GPT tables:

| LUN | Allowed ranges cover | Not covered |
|---:|---|---|
| 0 | `ssd`, head and part of `persist` | `misc`, `keystore`, `system`, `userdata` |
| 1 | head of `xbl` only | rest of `xbl`, `xbl_config` |
| 2–3 | `last_parti`, `cdt`, `ddr`, alignment areas | — |
| 4 | heads of `aop`, `tz`, `hyp` | **`abl`**, `boot`, `modem`, `devinfo`, `vbmeta`, `recovery` |
| 5 | `oppodycnvbk` head | `opporeserve*`, `modemst*` |

So even with a valid signed digest table, `program` cannot write `abl`,
`boot`, `devinfo` or `vbmeta` while VIP is enforced. That closes the
"flash a modified ABL" route at the programmer layer.

## Generic Qualcomm VIP, not OPPO's variant

The image contains `VIP is enabled, receiving the signed table of size %d`,
`Number of VIP hashes %d on initial table`, `VIP hash table accepted %d packet
%d` and the `MaxDigestTableSizeInBytes` configure parameter. It does **not**
contain OPPO's `EnableVip`, `sha256init` or `getsigndata`, which appear in
OPPO-specific VIP implementations. This is the stock Qualcomm mechanism.

## Live result (2026-11-11): VIP is off on this device

A dispatcher probe sent `erase` expecting a VIP refusal. The programmer
executed it (`Erasing the whole disk/LUN 0`, `UFS Format whole LUN`, ACK) and
formatted LUN 0. Recovery writes then succeeded without any digest table.
Conclusion: EL3 reports VIP off for this device/state, and the programmer
performs unrestricted writes. The static VIP code above is real but inactive
here. (The erase was an operational mistake and cost a full LUN 0 restore;
the device was recovered from the C.01 OTA and its own state dumps.)

So on this device the remaining barrier to a modified boot chain is not
Firehose policy but **AVB and the locked bootloader**.

## What this implies

There are three separate barriers, and the hash-table bypass only clears the
first:

1. PBL acceptance of the programmer — bypassed by fixing the outer SHA-256
   table.
2. Firehose authorization — VIP, decided in EL3, enforced by the dispatcher,
   the range table and the digest table.
3. Persistent boot chain — XBL authenticates ABL; ABL keeps unlock state in
   RPMB.

The next candidate is not another hash patch but the VIP predicate: forcing it
to report "VIP off" would skip the allow-list, the range check and the digest
check together. Whether EL3 or the storage stack enforces anything further is
unknown and would have to be tested read-only before any write.
