# rndis-mac

Native macOS userspace driver for USB RNDIS devices. Built primarily to talk
to a hakchi-modded **PC Engine Mini** from an Apple Silicon Mac, but the
protocol code is generic — it should work with any RNDIS gadget (e.g. older
Android phones in tethering mode, BeagleBone Black, hakchi-modded NES/SNES
Classic, custom Linux gadgets) once you tell it the right VID/PID and IPs.

## Why

macOS no longer ships an RNDIS driver, and the legacy `HoRNDIS` kext is dead
on Apple Silicon (kernel extensions require Reduced Security and the kext
APIs are being phased out). The "modern" alternative — a DriverKit
networking system extension — needs Apple to grant the
`com.apple.developer.driverkit.family.networking` entitlement, which they
generally do not give to individuals.

This project sidesteps both: it's a plain userspace daemon. It opens the USB
device with `nusb` (no libusb dependency), speaks the RNDIS control
protocol on EP0, shuffles RNDIS-framed Ethernet frames across the bulk
endpoints, and bridges them to a `utun` virtual interface created via the
standard `PF_SYSTEM` / `SYSPROTO_CONTROL` API. No kext. No DriverKit. No
Apple entitlement. No SIP downgrade. Runs as a regular binary (with `sudo`
only because configuring the utun's IP via `ifconfig` requires it).

## Status

Working end-to-end on macOS 15 / Apple Silicon. SSH, ICMP, FTP, and
arbitrary IP traffic over the bridge all confirmed. Tested against a
hakchi-modded PC Engine Mini.

## How it works

```
+----------------+        +-----------+        +-----------+        +--------------+
|  Mac apps      |  IPv4  |   utunN   |  L3↔L2 |  rndis-up |  USB   |  RNDIS gadget|
|  ssh / ping /  | <----> | (kernel)  | <----> |  (this    | <----> |  (Linux usb0 |
|  curl / ftp    |        |           |        |   daemon) |        |   on device) |
+----------------+        +-----------+        +-----------+        +--------------+
```

`rndis-up` does three things at once:

1. **RNDIS control plane**: opens the USB device, claims the two RNDIS
   interfaces, sends `INITIALIZE` / `QUERY` (MAC, link speed, MTU) /
   `SET PACKET_FILTER` over `SEND_ENCAPSULATED_COMMAND`, drains
   `INDICATE_STATUS` events, runs `KEEPALIVE` every 5 seconds.
2. **Data plane**: wraps each outgoing Ethernet frame in
   `RNDIS_PACKET_MSG` and submits it on bulk-OUT; reads bulk-IN and
   un-frames each packet.
3. **L2↔L3 shim**: macOS `utun` is layer-3 (IP only), but RNDIS carries
   layer-2 Ethernet. The daemon synthesizes an Ethernet header on outbound
   frames, learns the device's MAC from inbound traffic and ARP, and
   answers ARP requests for our own IP locally.

## Build

Requires Rust ≥ 1.75 and macOS 13+ (Apple Silicon or Intel).

```
git clone https://github.com/<your-fork>/rndis-mac
cd rndis-mac
cargo build --release
```

## Run

```
sudo ./target/release/rndis-up
```

This brings up a `utunN` interface, configures it with the default IPs
(`169.254.13.36` local, `169.254.13.37` peer — those are the values for a
hakchi-modded PC Engine Mini), and starts bridging. From another terminal:

```
ping 169.254.13.37
ssh root@169.254.13.37
```

To use a different RNDIS device, override the relevant defaults:

```
sudo ./target/release/rndis-up \
    --vid 18d1 --pid 4ee7 \
    --host-ip 192.168.42.129 \
    --peer-ip 192.168.42.1 \
    --host-mac 02:00:00:00:00:42
```

`rndis-up --help` lists every flag.

### Why `sudo`?

Only `ifconfig <utun> inet ... up` needs root. The USB and `utun` socket
opens themselves do not require privileges. The packaged LaunchDaemon
(below) runs as root automatically so you don't have to type `sudo` after
the initial install.

## Auto-start (LaunchDaemon)

If you want the bridge to come up at boot and survive plug/unplug cycles
without you running anything by hand:

```
./packaging/install.sh
```

That script will:

1. `cargo build --release` if needed,
2. install the binary to `/usr/local/bin/rndis-up`,
3. install `com.rndis-mac.plist` to `/Library/LaunchDaemons/`,
4. `launchctl bootstrap` it.

The daemon is `KeepAlive`, so the binary's internal reconnect loop plus
launchd's restart-on-exit means: plug in → connection comes up; unplug →
errors logged and process loops; replug → connection comes back. Logs go
to `/var/log/rndis-mac.log`.

To use non-default flags, edit `ProgramArguments` in the plist (or in
`packaging/com.rndis-mac.plist` before installing) and append your
`--vid` / `--pid` / `--host-ip` / `--peer-ip` / `--host-mac` arguments.

Uninstall:

```
./packaging/uninstall.sh
```

## Diagnostic binaries

The repo also builds four small tools that were used during development —
they're handy when bringing up a new device:

| Binary             | What it does                                                    |
| ------------------ | --------------------------------------------------------------- |
| `rndis-probe`      | Open the device, dump descriptors and class-specific info.      |
| `rndis-handshake`  | Run the full RNDIS control handshake, print MAC / link / MTU.   |
| `rndis-dump`       | Handshake + ARP probe + decode anything that comes back.        |
| `rndis-raw-rx`     | Bypass framing, dump raw bulk-IN bytes (cable-level debugging). |

If `rndis-up` doesn't work against your device, run `rndis-probe` first to
confirm the layout, then `rndis-handshake` to confirm the control plane.

## Repo layout

```
src/
  rndis.rs      RNDIS message encoder / decoder
  session.rs    USB open + handshake + bulk send/recv
  utun.rs       macOS utun control-socket wrapper
  bin/
    probe.rs    descriptor dumper
    handshake.rs  control-plane self-test
    dump.rs     ARP probe + frame decoder
    raw_rx.rs   raw bulk-IN dumper
    up.rs       the bridge daemon
```

## Limitations and notes

- **macOS only.** `utun.rs` is Darwin-specific. On Linux you don't need any
  of this (RNDIS host driver has been in-tree since forever).
- **`utun` is layer 3.** That means IP works fine, but anything that needs
  raw L2 (mDNS multicast, DHCP client, etc.) won't traverse the bridge as
  cleanly as a real Ethernet interface would. ARP is handled internally; if
  you need DHCP, build it as a userspace probe inside `up.rs`.
- **No IPv6 router-solicitation suppression.** `utun` will emit IPv6 RS
  frames; the daemon forwards them. Generally harmless.

## How this came to exist

A long Claude Code session, milestone by milestone:

1. enumerate the device, dump descriptors;
2. send `INITIALIZE`, see the device reply;
3. ARP the peer, see it reply;
4. open `utun`, bridge, ping the device.

The trickiest bug was self-inflicted: the original ARP sweep used the
device's own IP as the source, so the request that would have been
answered (`who-has 169.254.13.37`) was never sent. Lesson: always make
your scanner's source address something other than your target's.

## License

MIT — see [LICENSE](LICENSE).
