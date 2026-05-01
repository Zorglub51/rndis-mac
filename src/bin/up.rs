//! Milestone 4: bring up a utunN interface and bridge it to the RNDIS link.
//!
//! Topology:
//!     Mac apps  <-->  utunN  <-->  this daemon  <-->  USB  <-->  device
//!                     L3 IP        ARP shim,           bulk-OUT    Linux gadget
//!                                  Eth framing         bulk-IN     usb0
//!
//! The Mac side configures (via `ifconfig` once we know the interface name):
//!     ifconfig utunN inet 169.254.13.36 169.254.13.37 up
//! After that, `ping 169.254.13.37` from the Mac just works.

use anyhow::{anyhow, bail, Context, Result};
use rndis_mac::session::Session;
use rndis_mac::utun::{Utun, AF_INET, AF_INET6};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct Cfg {
    vid: u16,
    pid: u16,
    host_ip: [u8; 4],
    peer_ip: [u8; 4],
    host_mac: [u8; 6],
}

fn print_usage() {
    eprintln!(
        "rndis-up: bridge a USB RNDIS device to a macOS utun interface\n\n\
         Options (all have working defaults for a hakchi-modded PC Engine Mini):\n  \
           --vid HEX           USB vendor id (default 04e8)\n  \
           --pid HEX           USB product id (default 6863)\n  \
           --host-ip A.B.C.D   IP for our utun end (default 169.254.13.36)\n  \
           --peer-ip A.B.C.D   IP of the device (default 169.254.13.37)\n  \
           --host-mac XX:..:XX MAC we present to the device (default 02:00:00:00:00:36)\n  \
           -h, --help          show this message"
    );
}

fn parse_args() -> Result<Cfg> {
    let mut cfg = Cfg {
        vid: 0x04E8,
        pid: 0x6863,
        host_ip: [169, 254, 13, 36],
        peer_ip: [169, 254, 13, 37],
        host_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x36],
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "--vid" => cfg.vid = u16::from_str_radix(&args.next().ok_or_else(|| anyhow!("--vid"))?, 16)?,
            "--pid" => cfg.pid = u16::from_str_radix(&args.next().ok_or_else(|| anyhow!("--pid"))?, 16)?,
            "--host-ip" => cfg.host_ip = parse_ip(&args.next().ok_or_else(|| anyhow!("--host-ip"))?)?,
            "--peer-ip" => cfg.peer_ip = parse_ip(&args.next().ok_or_else(|| anyhow!("--peer-ip"))?)?,
            "--host-mac" => cfg.host_mac = parse_mac(&args.next().ok_or_else(|| anyhow!("--host-mac"))?)?,
            other => bail!("unknown argument: {other} (try --help)"),
        }
    }
    Ok(cfg)
}

fn parse_ip(s: &str) -> Result<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        bail!("bad IP: {s}");
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().map_err(|_| anyhow!("bad IP: {s}"))?;
    }
    Ok(out)
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("bad MAC: {s}");
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).map_err(|_| anyhow!("bad MAC: {s}"))?;
    }
    Ok(out)
}

fn main() -> Result<()> {
    let cfg = parse_args()?;
    // Outer reconnect loop: tolerate the device disappearing/reappearing.
    loop {
        match run_once(&cfg) {
            Ok(()) => {
                eprintln!("session ended cleanly; waiting 2s before reconnect");
            }
            Err(e) => {
                eprintln!("session error: {e:#}");
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn run_once(cfg: &Cfg) -> Result<()> {
    let host_ip = cfg.host_ip;
    let peer_ip = cfg.peer_ip;
    let host_mac = cfg.host_mac;
    let s = Arc::new(Session::open(cfg.vid, cfg.pid)?);
    println!(
        "RNDIS up — device MAC reported as {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        s.mac[0], s.mac[1], s.mac[2], s.mac[3], s.mac[4], s.mac[5]
    );

    let utun = Arc::new(Utun::create()?);
    println!("created {}", utun.name);

    // Configure addresses on the utun. ifconfig is the simplest path on macOS.
    let status = Command::new("ifconfig")
        .args([
            &utun.name,
            "inet",
            &fmt_ip(host_ip),
            &fmt_ip(peer_ip),
            "netmask",
            "255.255.255.255",
            "up",
        ])
        .status()
        .context("ifconfig")?;
    if !status.success() {
        return Err(anyhow!("ifconfig {} failed", utun.name));
    }
    println!("configured {}: {} -> {}", utun.name, fmt_ip(host_ip), fmt_ip(peer_ip));

    // ARP cache for the device's Ethernet MAC, learned from incoming frames.
    let peer_mac: Arc<Mutex<Option<[u8; 6]>>> = Arc::new(Mutex::new(None));

    // Prime the ARP cache on the device with a gratuitous-ish announcement,
    // and ask "who has peer_ip" so we learn the device's MAC.
    let arp = build_arp(host_mac, [0xff; 6], host_ip, peer_ip, 1);
    s.send_eth(&arp)?;

    // Thread: bulk-IN → utun (with ARP shim).
    let s_rx = Arc::clone(&s);
    let utun_rx = Arc::clone(&utun);
    let peer_mac_rx = Arc::clone(&peer_mac);
    let s_tx_for_rx = Arc::clone(&s);
    thread::spawn(move || loop {
        match s_rx.recv_eth() {
            Ok(frames) => {
                for f in frames {
                    if let Err(e) = handle_eth_in(&f, &utun_rx, &peer_mac_rx, &s_tx_for_rx, host_ip, peer_ip, host_mac) {
                        eprintln!("rx handler: {e:#}");
                    }
                }
            }
            Err(e) => {
                eprintln!("bulk in fatal: {e:#}");
                return;
            }
        }
    });

    // Thread: utun → bulk-OUT (synthesize ethernet header).
    let s_tx = Arc::clone(&s);
    let utun_tx = Arc::clone(&utun);
    let peer_mac_tx = Arc::clone(&peer_mac);
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match utun_tx.read_packet(&mut buf) {
                Ok((af, len)) => {
                    let payload = &buf[4..4 + len];
                    let dst_mac = match *peer_mac_tx.lock().unwrap() {
                        Some(m) => m,
                        None => {
                            // We haven't learned the peer MAC yet — drop and re-ARP.
                            let arp = build_arp(host_mac, [0xff; 6], host_ip, peer_ip, 1);
                            let _ = s_tx.send_eth(&arp);
                            continue;
                        }
                    };
                    let ethertype = match af {
                        AF_INET => [0x08, 0x00],
                        AF_INET6 => [0x86, 0xDD],
                        _ => continue,
                    };
                    let mut frame = Vec::with_capacity(14 + payload.len());
                    frame.extend_from_slice(&dst_mac);
                    frame.extend_from_slice(&host_mac);
                    frame.extend_from_slice(&ethertype);
                    frame.extend_from_slice(payload);
                    if let Err(e) = s_tx.send_eth(&frame) {
                        eprintln!("bulk out: {e:#}");
                    }
                }
                Err(e) => {
                    eprintln!("utun read: {e:#}");
                    return;
                }
            }
        }
    });

    // Periodically refresh ARP if we haven't learned the peer MAC yet, and
    // run RNDIS keepalives.
    let s_ka = Arc::clone(&s);
    let peer_mac_ka = Arc::clone(&peer_mac);
    loop {
        thread::sleep(Duration::from_secs(5));
        if peer_mac_ka.lock().unwrap().is_none() {
            let arp = build_arp(host_mac, [0xff; 6], host_ip, peer_ip, 1);
            let _ = s_ka.send_eth(&arp);
        }
        if let Err(e) = s_ka.keepalive() {
            eprintln!("keepalive failed: {e:#}");
            break Ok(());
        }
    }
}

fn handle_eth_in(
    f: &[u8],
    utun: &Utun,
    peer_mac: &Mutex<Option<[u8; 6]>>,
    s: &Session,
    host_ip: [u8; 4],
    peer_ip: [u8; 4],
    host_mac: [u8; 6],
) -> Result<()> {
    if f.len() < 14 {
        return Ok(());
    }
    let _dst = &f[0..6];
    let src = &f[6..12];
    let et = u16::from_be_bytes([f[12], f[13]]);
    match et {
        0x0806 => {
            // ARP — learn peer MAC, answer requests for host_ip.
            if f.len() < 14 + 28 {
                return Ok(());
            }
            let p = &f[14..14 + 28];
            let op = u16::from_be_bytes([p[6], p[7]]);
            let sender_hw: [u8; 6] = p[8..14].try_into().unwrap();
            let sender_ip: [u8; 4] = p[14..18].try_into().unwrap();
            let target_ip: [u8; 4] = p[24..28].try_into().unwrap();
            if sender_ip == peer_ip {
                *peer_mac.lock().unwrap() = Some(sender_hw);
                eprintln!(
                    "[learned peer MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}]",
                    sender_hw[0],
                    sender_hw[1],
                    sender_hw[2],
                    sender_hw[3],
                    sender_hw[4],
                    sender_hw[5]
                );
            }
            if op == 1 && target_ip == host_ip {
                // Build ARP reply.
                let reply = build_arp(host_mac, sender_hw, host_ip, sender_ip, 2);
                s.send_eth(&reply)?;
            }
        }
        0x0800 => {
            let payload = &f[14..];
            utun.write_packet(AF_INET, payload)?;
            // Opportunistically learn peer MAC from any IPv4 frame.
            if peer_mac.lock().unwrap().is_none() {
                let mut m = [0u8; 6];
                m.copy_from_slice(src);
                *peer_mac.lock().unwrap() = Some(m);
            }
        }
        0x86DD => {
            let payload = &f[14..];
            utun.write_packet(AF_INET6, payload)?;
        }
        _ => {}
    }
    Ok(())
}

fn build_arp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    tgt_ip: [u8; 4],
    op: u16,
) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x06]);
    f.extend_from_slice(&[0x00, 0x01]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.push(6);
    f.push(4);
    f.extend_from_slice(&op.to_be_bytes());
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&src_ip);
    let target_hw = if op == 1 { [0u8; 6] } else { dst_mac };
    f.extend_from_slice(&target_hw);
    f.extend_from_slice(&tgt_ip);
    f
}

fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
