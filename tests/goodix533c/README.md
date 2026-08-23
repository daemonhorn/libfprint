# goodix533c umockdev test fixture

Real USB traffic captured from a physical `27c6:533c` sensor via
`usbmon`/`tshark`, for `umockdev-run -p` replay -- same mechanism used by
`tests/goodixmoc/`, `tests/fpcmoc/`, `tests/elanmoc/`, etc. in this tree.

This is a copy of the fixture originally captured and vetted in the parent
project at `tests/goodix533c/` (outside this submodule); see that
directory's own README.md for the full capture provenance notes. The files
here are byte-identical copies, renamed to match this tree's convention
(`custom.pcapng`/`custom.py`, per `tests/umockdev-test.py`) rather than
moved -- the original is left in place.

- `device` -- `umockdev-record`'s sysfs/udev description of the real
  device (vendor/product IDs, descriptors, interfaces, endpoints).
- `custom.pcapng` -- one full session: `nop -> reset -> read chip ID ->
  read OTP -> TLS-PSK handshake -> upload_config_mcu -> FDT baseline ->
  one mcu_get_image capture (reference frame, gain 0xc2)`.
- `custom.py` -- driven by `tests/umockdev-test.py` (invoked via `meson
  test`), exercises device discovery and feature-flag assertions against
  the replayed session. It deliberately stops there and does not call
  `open_sync()` -- see "Replay status" below for why.

## Deliberately finger-absent

This fixture stops after the no-finger reference-frame capture and never
calls `wait_for_finger()`/captures a live frame. The PSK for this whole
device family is public (all-zero), so anyone with the pcapng can decrypt
every `mcu_get_image` payload in it. A live capture would be a real,
recoverable fingerprint image committed to a public repo -- so it was
deliberately not what got recorded.

**No new capture may ever be added here that contains a finger-present
`mcu_get_image` reply, for any reason** -- not to test finger-detect-wait,
not to test live-capture/flat-field, and not to test SIGFM
enroll/verify/identify (see below -- those vfuncs are wired up in the
driver now, but nothing in this fixture can safely exercise them). Any
such fixture must be captured and vetted by a human outside of an
automated agent, exactly as this one was.

## Replay status (important -- read before trusting this fixture)

### The original zero-payload bug: root cause found, and fixed

The first cut of this fixture (still the version described in stale form
below until this section was rewritten) could not replay past the
driver's second open() command (`0xa8`, `GOODIX_CMD_FIRMWARE_VERSION`):
every bulk-IN (`0x83`) completion in the capture had `usb.data_len == 0`
despite `usb.urb_len` correctly reporting the real transfer size --
metadata preserved, payload always redacted. Tool choice was
conclusively ruled out first: `tools/recapture_fixture_dumpcap.sh` in the
parent project captures via `dumpcap` directly (bypassing tshark's
wrapper) and reproduces the *identical* symptom, including on the
14,338-byte real image-transfer frame.

**Root cause: Linux kernel lockdown mode (`confidentiality`), which
redacts USB payload capture system-wide, including for root.** Confirmed
directly on the host that produced every earlier attempt:

- `cat /sys/kernel/security/lockdown` reports `none [integrity]
  confidentiality` -- confidentiality mode active.
- The usbmon **text** interface (`/sys/kernel/debug/usb/usbmon/<N>u`)
  returns `Operation not permitted` (EPERM) even as root -- the kernel's
  `LOCKDOWN_USB` restriction blocking a debugfs interface outright, not a
  DAC permission issue (root bypasses DAC; it cannot bypass a lockdown
  LSM check).
- The usbmon **binary** interface (what both `tshark` and `dumpcap` use)
  stays readable, but has its captured-data length forced to 0 on every
  bulk-IN completion for this device, while `urb_len` (the real transfer
  size) stays correct -- exactly the "metadata preserved, payload
  redacted" shape `LOCKDOWN_USB` produces, and exactly what both tool
  choices independently reproduced.

This is intentional kernel behavior (typically auto-enabled by Secure
Boot), not a bug in the driver, the test harness, or any capture tool --
and not something to work around by changing lockdown/Secure Boot
settings on a real machine.

**Fix: capture from inside a VM whose guest kernel has no lockdown
enabled.** The physical sensor was passed through via QEMU
(`-device usb-host,vendorid=0x27c6,productid=0x533c`) to the existing
`vm/` Ubuntu 20.04 cloud image (already used earlier in this project for
a different capture, see `findings/vm-capture-analysis.md`), running the
same finger-absent `capture_fixture_session.py` inside the guest while
`tshark` captured on the guest's own `usbmonN`. Verified byte-exact:
every one of the 26 bulk-IN completions in the resulting capture has
`usb.data_len == usb.urb_len`, summing to 14,835/14,835 bytes across the
whole session, including the full 14,338-byte encrypted image-capture
frame. The reusable capture script is
`vm/usbmon-capture-in-vm.sh` in the parent project (plus a small
`vm/patch_future_annotations.py` helper, needed because the VM's stock
Python 3.8 predates the PEP 604/585 type-hint syntax the vendored
`goodix-fp-dump-nikicat` driver uses) -- read its header comment before
re-running it, since a future finger-present capture (see "Deliberately
finger-absent" above) will need the same mechanism.

### Current open item: umockdev replay desync on the full-payload capture

`custom.pcapng` now carries genuinely complete payload data (confirmed
above), but replaying it against the driver surfaces a **different,
second problem**, not present with the old zero-payload capture:

```
umockdev-pcap.vala:158: Replay may be stuck: Reaping discard URB of type
BULK, for endpoint 0x01 with length 64 without corresponding submit
```

...followed by the same `Command timed out: 0xa8` outcome. Diagnostic
work so far (with `G_MESSAGES_DEBUG=all umockdev-run ...`):

- The two captures are structurally near-identical for the whole
  `nop`/`firmware_version` exchange -- same submit/complete ordering,
  same cancelled-read pattern for `nop`'s tolerant no-reply timeout, same
  write byte content. Replaying the *old* zero-payload capture against
  the current driver build reproduces its originally-documented behavior
  exactly (two `Unknown pack flags: 0x00` warnings, then the timeout) --
  no "stuck"/discard message at all.
- The divergence is therefore specifically triggered by the presence of
  real, non-empty reply payload (the `firmware_version` reply now
  arrives as a real `COMMAND_ACK` then real `COMMAND_FIRMWARE_VERSION`
  data, versus two empty reads before) -- something in umockdev's own
  URB submit/complete bookkeeping desyncs once there's real data to
  track, rather than an ordering or content mismatch in the capture
  itself.
- Root-hub traffic interleaving (device address 1 vs the sensor's device
  address 2) was ruled out as the cause -- filtering the capture to only
  the sensor's own traffic (`usb.device_address == 2`) makes no
  difference.

**Not yet resolved.** `custom.py` is therefore left as-is (device
discovery and feature-flag assertions only, `open_sync()` still not
called) until this is understood -- re-enabling it on a capture that is
known not to replay would trade a documented, honest gap for a silently
broken test. `custom.pcapng` itself is worth keeping as-is regardless:
it is the *complete, correct* protocol capture (confirmed byte-exact),
which is what any future recapture would need to start from, and is
already strictly more useful than the zero-payload version for anyone
debugging this further (e.g. by decoding it with
`tools/decode_capture.py`/`tools/parse_capture.py` in the parent
project).

## Current scope and limitations

`goodix533c.c` currently wires up `dev_class->open`/`->close`/`->enroll`/
`->verify`/`->identify`/`->cancel` (via the concurrent SIGFM work), with
`features` derived by `fpi_device_class_auto_initialize_features()`:
`VERIFY`, `IDENTIFY`, and `ALWAYS_ON` are set; `CAPTURE` is deliberately
NOT set (`dev_class->capture` itself is left NULL -- the open()+one-frame
capture path is only exercised via the test-only
`goodix533c-capture-test` binary, not the public FPrint API); no
`STORAGE*` bits are set (no on-chip storage -- this driver's design is
match-on-host via SIGFM, see `sigfm/` and `libfprint/drivers/goodix533c/`).
Accordingly `custom.py`:

- Does exercise: device enumeration and driver-name/feature-flag
  assertions matching the current wiring.
- Does NOT exercise: `open_sync()`/`close_sync()` (see "Verified replay
  result" above -- this specific capture file cannot support it),
  `enroll_sync()`, `verify_sync()`, `identify_sync()`, or any on-chip
  storage calls. The latter would require driving the device past what
  this fixture could ever safely record (a live finger-present frame),
  which is exactly what must not be committed, on top of the open()
  replay gap making it moot anyway.

**Follow-up needed, in two independent stages:**

1. **Resolve the umockdev replay desync described in "Replay status"
   above.** The capture itself is no longer the blocker (it has complete
   payload data, byte-verified); what's blocking is umockdev's own
   submit/complete bookkeeping getting stuck partway through replaying
   it. Once `custom.pcapng` replays cleanly end to end, add
   `open_sync()`/`close_sync()` back into `custom.py` (removed from this
   version because the fixture couldn't support them) and confirm they
   pass.
2. **Then, once SIGFM enroll/verify/identify work is complete**, extend
   `custom.py` (or add a second fixture-specific test file) to drive
   `enroll_sync()`/`verify_sync()`/`identify_sync()`, modeled on
   `tests/fpcmoc/custom.py` or `tests/elanmoc/custom.py` (both
   match-on-device though, not match-on-host -- so adapt rather than copy
   the `STORAGE*` assertions; this driver has none of those). This needs
   a *further* new capture that includes real finger-present
   `mcu_get_image` replies -- which, per the constraint above, must be
   captured and safety-reviewed by a human, never generated by an agent,
   and only committed if the human is certain they're comfortable with
   those frames being third-party-decryptable (the PSK is public). Use
   `vm/usbmon-capture-in-vm.sh` (parent project) for the underlying
   capture mechanism -- it's the only one confirmed to retain full
   payload data on a lockdown-enabled host.

## Replay

```sh
umockdev-run -d device \
  -p /sys/devices/pci0000:00/0000:00:14.0/usb3/3-3=custom.pcapng \
  -- <program that talks to 27c6:533c>
```

The syspath is specific to the machine this was captured on but is only
used as a mock sysfs label by umockdev -- any syspath works as long as
the `-p` flag's key matches the `P:` line in `device` with `/sys`
prepended. `tests/umockdev-test.py` derives this automatically from the
`device` file, so `meson test goodix533c` does not need the path spelled
out manually.

**Known limitation** (inherited from the original capture): replaying
against `vendor/goodix-fp-dump-nikicat`'s Python reference driver directly
fails at device-open (PyUSB's `protocol.py` makes `is_kernel_driver_active`/
`set_configuration` calls that a libfprint C driver using `GUsbDevice`/
`g_usb_device_claim_interface` would not). This fixture targets the native
libfprint `goodix533c` driver, not the Python reference implementation --
though see "Verified replay result" above, since even against the native
driver this fixture currently can't complete `open()`.
