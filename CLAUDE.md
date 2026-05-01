# Notes for Claude (or anyone) working on this repo

This is a macOS userspace RNDIS driver. Keep that constraint in mind:
no kext, no DriverKit, no entitlements that would require Apple approval.
If a change would push toward any of those, surface it as a tradeoff
rather than just doing it.

## Module layout (don't break the seams)

- `src/rndis.rs` — protocol-level. Pure encoder/decoder, no I/O. Add new
  OIDs/messages here.
- `src/session.rs` — USB + RNDIS handshake + bulk send/recv. The four
  diagnostic binaries depend on its public API; if you rename methods,
  update them all.
- `src/utun.rs` — Darwin-specific tunnel wrapper. Keep this the *only*
  place with `libc` / Darwin syscalls.
- `src/bin/up.rs` — bridge daemon. The L2↔L3 shim and ARP handling live
  here.
- `src/bin/{probe,handshake,dump,raw_rx}.rs` — diagnostic tools. Useful
  when bringing up a new device; don't delete them.

## Things that bit during initial development (don't repeat)

- macOS leaves RNDIS devices unconfigured (no driver matches), so
  `set_configuration(1)` is required before claiming interfaces.
- `INDICATE_STATUS` messages can arrive on the control endpoint at any
  time and will be picked up by `GET_ENCAPSULATED_RESPONSE` instead of
  the response you wanted. The session loop drains them.
- An ARP sweep that uses the target's own IP as its source will silently
  miss the target. If you write any scanning code, keep source ≠ target.
- `utun` is layer-3 only. The bridge handles ARP locally; do not assume
  the kernel will do it for you.

## Testing

There's no test suite yet — verification was end-to-end with a physical
device. If you add tests, keep them around the pure protocol code in
`rndis.rs` (parser/builder round-trips). The USB and utun layers need
hardware.
