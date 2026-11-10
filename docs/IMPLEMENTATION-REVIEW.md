# Implementation review corrections

Date: 2026-11-10. Scope: the 20 findings in the implementation/research
review of commit `f31a9d3`. Corrections are host-side; verification is offline.
No hardware discovery, USB probes, flashing, or storage commands form part
of this review. This is a historical snapshot: the live signed-programmer
validation came later and is recorded in [VERIFICATION.md](VERIFICATION.md).

| Review issue | Correction |
|---|---|
| 1. USB input treated as a stream | Receive into maxpacket-multiple buffers; logical reads consume a retained queue, preserving surplus bytes. |
| 2. Late programmer validation | Read and validate programmer/resources before opening a transport or executing host steps. |
| 3. Double-open | One layer owns open/close; serving does not open an already-open transport again. |
| 4. Invalid CDC request | Correct request signature and expose setup errors; CDC requests require explicit `--usb-cdc`. |
| 5. Disconnect bypasses recovery | Recognize backend disconnection errors; reacquire before continuing at supported transitions. |
| 6. Strict host mode only logs | Validate expected commands, lengths, image IDs, offsets, sizes and permitted status before the next fixed payload. |
| 7. Read deadline overrun | Enforce a monotonic deadline across empty packets and partial reads; separate exact reads from prompt short reads. |
| 8. Rejection keeps serving | Terminate the serve state machine on terminal rejection. |
| 9. USB paths differ | All bus/address selection uses `UsbEdl`; aligned OUT termination failures propagate. |
| 10. Unused discovery timeouts | Apply bounded discovery/reconnect deadlines using `--port-timeout` / `--reopen-timeout`. |
| 11. Unbounded programmer requests | Reject invalid command sizes, image IDs, ranges and excessive requested chunks before allocation; no implicit out-of-range zero padding. |
| 12. Selection can change devices | Require an unambiguous target and retain physical bus/port identity across rediscovery; address can change. |
| 13. Linux bound driver | Detach a bound kernel driver where supported and restore it on close. |
| 14. DONE status ignored | Validate DONE_RESP size and status; `0` is pending and `1` is complete. |
| 15. Optional custom hash | Require explicit matching SHA-256 for a custom segment1. |
| 16. Unreachable zero generation | Generate a missing `0xbf8` zero block before its hash check. |
| 17. ping dry-run | Inspect ping without loading private resources or using a nonexistent mode argument. |
| 18. Sahara-only exit status | Completed Sahara with `--xml none` succeeds. |
| 19. Parser recovery stalls | Reject malformed framing promptly; incomplete packets remain buffered. |
| 20. Numeric CLI bounds | Reject invalid timeout/retry/reset-count values during argument parsing. |

## Public verification

Install `requirements.txt`, then run without payload resources or hardware:

```bash
python3 -m unittest discover -s tests -v
python3 pblexp_macos.py self-test
python3 pblexp_macos.py ping --dry-run
```

Tests use synthetic fixtures, packet-preserving USB mocks, and protocol
state-machine cases. The separate `check-resources` command verifies private
resource integration. Passing these checks establishes host behavior under
the tested mocks, not USB interoperability or exploit execution. The final
implementation report should record actual command results; no historical
private-resource test count is claimed here.

For `serve` / `all`, `0` means completed Sahara with `--xml none`, or a
programmer XML response if a ping was requested; `2` means accepted transfer
without required completion/XML; `3` means rejection or incomplete transfer.
`ping` returns `0` for a response and `2` for none. Resource/input/backend
failures exit `1`; argument parsing errors exit `2`. A response is an execution
ping result, including NAK, and does not imply configure was accepted.

## Protocol and research corrections

All offsets below index bytes on the wire, starting at command byte zero:

| Packet | Total length | Fields |
|---|---:|---|
| READ_DATA64 (`0x12`) | `0x20` | image u64 `+0x08`, offset u64 `+0x10`, size u64 `+0x18` |
| END_IMAGE_TX (`0x04`) | `0x10` | image u32 `+0x08`, status u32 `+0x0c` |
| DONE host request (`0x05`) | `0x08` | command and length only |
| DONE_RESP (`0x06`) | `0x0c` | status u32 `+0x08`: pending `0`, complete `1` |

These layouts and image-range/completion checks follow
[qdl's Sahara implementation](https://github.com/linux-msm/qdl/blob/master/src/sahara.c).
The older Windows report's shifted offsets may describe managed-object
accesses rather than byte-array indexes; that explanation requires the
original artifact to confirm. Absence of an incoming DONE handler does not
show whether the Windows host sends DONE. Its post-END_IMAGE payload needs
re-examination.

[libusb documents bulk overflow](https://libusb.sourceforge.io/api-1.0/libusb_packetoverflow.html):
a logical 8-byte header read cannot safely become an 8-byte USB receive
buffer. [qdl's USB implementation](https://github.com/linux-msm/qdl/blob/master/src/usb.c)
provides the reference for direct claim, kernel-driver handling and aligned
OUT ZLP. Neither receive buffering nor aligned-write termination explains
the historical first 48-byte Hello OUT timeout.

[Apple's ACM matcher](https://github.com/apple-oss-distributions/AppleUSBCDCDriver/blob/main/Plists/AppleUSBCDCACMControl-Info.plist)
uses class/subclass `2/2`; the observed vendor interface does not match it.
[Linux qcserial](https://github.com/torvalds/linux/blob/master/drivers/usb/serial/qcserial.c)
supports the vendor QDL interface and can expose `ttyUSB`. A Qualcomm Windows
COM driver does not establish `usbser.sys` CDC traffic. CDC setup remains an
opt-in hypothesis pending a Windows USB capture. Historical descriptor EIO
is evidence of a failed request, not proof of subsequent PBL state causation.

## Similar projects

| Project | Useful comparison | Limit |
|---|---|---|
| [linux-msm/qdl](https://github.com/linux-msm/qdl) | Sahara layouts, ranges, DONE, USB lifecycle and ZLP | Generic loader; no evidence for this exact exploit exchange. |
| [bkerler/edl](https://github.com/bkerler/edl) | Python transport, CDC helper signatures, loader flow | Contains broad compatibility workarounds; target evidence is still needed. |
| [qualcomm/qdlrs](https://github.com/qualcomm/qdlrs) | Separate protocol library/backends/CLI and skip-hello option | No demonstrated RMX1901 175-reset sequence. |
| [alephsecurity/firehorse](https://github.com/alephsecurity/firehorse) | Programmer-focused exploitation research | A different stage from PBL/Sahara transport; not an RMX1901 unlock. |

The Windows baseline, private resource hashes, and C.01 ABL/TA conclusions
remain historical research records. The public checkout lacks the raw
artifacts needed for independent reproduction. Loading a signed programmer
alone does not demonstrate bypass; a cold-device control is still needed.

## Verification result

The integrated offline suite passes: **64 tests** using synthetic USB and
Sahara fixtures. It also passes with `python3 -S` (site packages disabled).
The CLI self-test and both ping dry-run forms pass without proprietary
resources. Source/test compilation, Python 3.10 grammar checks, and
`git diff --check` pass. These commands were run with Python 3.15; the grammar
check alone does not establish runtime compatibility on Python 3.10. No live device
was enumerated or claimed for these checks. USB reconnection is tested for
initial loader HELLO writes/reads and completed-Sahara to Firehose transitions;
a disconnect during active programmer transfer aborts rather than replaying
unknown bytes. USB selection retains physical port location, not authenticated
unit identity. When no physical port path is available, a changed USB address
is not automatically accepted. Serial handoff uses the original COM/path and
does not discover renamed serial nodes.
