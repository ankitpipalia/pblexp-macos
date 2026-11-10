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

## Remaining limits

- **Hardware behavior is unvalidated.** The native macOS host/serve sequence
  has not completed a live run. The first 48-byte Hello710 bulk-OUT timeout
  remains unexplained.
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
