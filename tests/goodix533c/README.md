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
  `open_sync()` -- see "Verified replay result" below for why.

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

## Verified replay result (important -- read before trusting this fixture)

Replaying `custom.pcapng` against the real, currently-built `goodix533c`
driver (both directly via the `goodix533c-capture-test` binary, and via
`custom.py`/`meson test`) was checked while adding this fixture to this
submodule. It does **not** get as far as the protocol summary above
implies. Concretely:

```sh
$ umockdev-run -d device \
    -p /sys/devices/pci0000:00/0000:00:14.0/usb3/3-3=custom.pcapng \
    -- .../builddir/libfprint/goodix533c-capture-test
Found: 0 (Goodix 27c6:533c Fingerprint Sensor) - driver goodix533c
Opening 0 ...

(process:NNNNN): libfprint-goodix533c-WARNING **: Unknown pack flags: 0x00

(process:NNNNN): libfprint-goodix533c-WARNING **: Unknown pack flags: 0x00
open() FAILED: Command timed out: 0xa8
```

`0xa8` is `GOODIX_CMD_FIRMWARE_VERSION`, the *second* command the driver's
open() sequence sends (after `nop`, whose reply -- or lack of one -- the
driver already tolerates). Under the standard `meson test` driver-test
harness, which sets `G_DEBUG=fatal-warnings`, the same underlying
condition instead aborts the process with `SIGTRAP` on the "Unknown pack
flags: 0x00" warning rather than reaching the timeout message, because
that warning becomes fatal.

Root cause, confirmed with `tshark`'s decoded USB URB fields (not just a
manual hex read) across the *entire* capture file: every completion event
on the fingerprint device's (bus 3, address 6) bulk-IN endpoint (address
`0x83`) has `usb.data_len == 0` -- i.e. **no bulk-IN reply payload was
ever captured for this device, anywhere in this file**, even though every
outgoing bulk-OUT request was captured in full (including the later-stage
TLS ClientHello/PSK and config-upload writes -- confirmed via
`usb.endpoint_address.direction` to genuinely be host-to-device, not
misattributed replies) and the control-endpoint (EP0) enumeration traffic
has real payload. This holds for every command, not just
firmware_version -- firmware_version simply happens to be the first
command in open() that actually requires a substantive reply (`nop`'s
reply is optional by design).

This finding was cross-checked with a control, since it's a strong claim
about an existing, already-vetted fixture: the same query
(`usb.endpoint_address==0x83 && usb.data_len>0`) against
`tests/goodixmoc/custom.pcapng` (a single-device capture with no bus
noise, known-good in upstream CI) returns 124 hits on its own endpoint
`0x83`, confirming both that the methodology correctly detects real
captured payload when present, and that a genuinely-replayable fixture
does carry it throughout. `goodix533c/custom.pcapng` returns 0 hits on
the same query, restricted to its own device's address (6) to exclude
unrelated bus traffic from another USB device (a Bluetooth adapter,
address 4) and the root hub (address 1) that happen to share the same
capture window.

That the driver's outgoing requests visibly *progress* through the whole
open() sequence in this capture (firmware_version, PSK read, reset, chip
ID/OTP reads, then a multi-packet TLS ClientHello/PSK and config-upload
write sequence) shows the real hardware genuinely replied at each stage
during the original live session -- otherwise the driver could never
have gotten far enough to send those later commands. What's missing is
specifically the *captured* reply payload, i.e. a property of how this
file was recorded, not of what happened on the wire when it was recorded.

**Practical effect on `custom.py`**: it does not call `open_sync()` (or
anything past it) at all, precisely because of this gap -- see the file
for the reasoning inline. It only asserts device discovery and feature
flags, which are fully verifiable against this fixture. `meson test`'s
`goodix533c` entry is expected to PASS with that reduced scope. A
previous draft of this fixture called `open_sync()`/`close_sync()`
unconditionally and documented the resulting failure instead of avoiding
it; that was reverted in favor of keeping the suite green and putting the
gap here, in the README, and in the task report instead of in a
permanently-red test.

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

1. **Fix the replay gap first.** A corrected `custom.pcapng` (or a
   replacement fixture) is needed that retains bulk-IN reply payload
   data -- still finger-absent, still stopping before any live
   `mcu_get_image` reply, just captured with a method that doesn't drop
   the device's response bytes. Once that exists, add
   `open_sync()`/`close_sync()` back into `custom.py` (they were removed
   from this version specifically because the current fixture can't
   support them -- see "Verified replay result" above) and confirm they
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
   those frames being third-party-decryptable (the PSK is public).

Neither of the two new captures described above were made as part of
adding this fixture.

**Snaplen ruled out as the cause.** After this fixture was added, two
fresh finger-absent recapture attempts were made (via
`capture_fixture_session.py`, same safe no-finger-only script, using
`tshark -i usbmon3 -s 0 ...` and then `-s 65535 ...` -- explicit
unlimited and explicit-large snap lengths respectively) specifically to
test whether a truncated capture snaplen was the cause. Both attempts
reproduced the exact same result: every bulk-IN (`0x83`) completion
event capped at exactly 64 bytes total frame length with 0 bytes of
captured payload, identical to the original fixture. Raw hex inspection
of one such frame (`tshark -x`) confirms the 64 bytes are consumed
entirely by usbmon's own binary capture header, with no payload bytes
attached at all -- not a truncated-but-present payload, a genuinely
absent one. This means the gap is not a tshark/dumpcap snaplen flag
issue; the actual cause is some other property of how `usbmon`'s
binary interface is capturing (or not capturing) this device's
bulk-IN completions on this system/kernel, not yet identified. Both
recapture attempts were deleted (they added no value and, being
finger-absent, carried no sensitivity, but there was no reason to keep
them). Whoever picks up "fix the replay gap" next should start by
ruling out something other than snaplen -- e.g. usbmon's ring buffer
size (`/sys/kernel/debug/usb/usbmon/` / `MON_IOCT_RING_SIZE`), a
`usbmon0u` text-mode capture as a simpler diagnostic cross-check, or
capturing via `dumpcap` directly instead of through `tshark`'s
wrapper.

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
