//! Milestone 3: handshake, ARP-probe the hakchi default IPs, dump replies.

use anyhow::Result;
use rndis_mac::session::Session;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const HOST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

fn main() -> Result<()> {
    let s = Arc::new(Session::open(0x04E8, 0x6863)?);
    println!(
        "session up — device MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} mtu {}",
        s.mac[0], s.mac[1], s.mac[2], s.mac[3], s.mac[4], s.mac[5], s.mtu
    );

    // Reader thread.
    let s_rx = Arc::clone(&s);
    thread::spawn(move || loop {
        match s_rx.recv_eth() {
            Ok(frames) => {
                for f in frames {
                    describe(&f);
                }
            }
            Err(e) => {
                eprintln!("rx error: {e:#}");
                return;
            }
        }
    });

    // Device is at 169.254.13.37. Use .36 as our source and ask for .37.
    let src = [169u8, 254, 13, 36];
    let tgt = [169u8, 254, 13, 37];
    let frame = build_arp_request(HOST_MAC, src, tgt);
    for _ in 0..3 {
        s.send_eth(&frame)?;
        thread::sleep(Duration::from_millis(80));
    }
    println!("ARP who-has 169.254.13.37 from 169.254.13.36 (x3)");

    // ICMPv6 neighbor solicitation to the device's link-local address.
    // Link-local from MAC: fe80::(mac[0]^0x02):mac[1]:mac[2]:ff:fe:mac[3]:mac[4]:mac[5]
    let m = s.mac;
    let mut iid = [0u8; 8];
    iid[0] = m[0] ^ 0x02;
    iid[1] = m[1];
    iid[2] = m[2];
    iid[3] = 0xff;
    iid[4] = 0xfe;
    iid[5] = m[3];
    iid[6] = m[4];
    iid[7] = m[5];
    let mut tgt6 = [0u8; 16];
    tgt6[0] = 0xfe;
    tgt6[1] = 0x80;
    tgt6[8..].copy_from_slice(&iid);
    let frame = build_ipv6_ns(HOST_MAC, &tgt6);
    s.send_eth(&frame)?;
    println!("ICMPv6 NS for device link-local");

    // Wait for replies / unsolicited traffic.
    thread::sleep(Duration::from_secs(8));

    // Diagnostic: query device counters to see if our OUTs were received.
    let print_u32 = |label: &str, oid: u32| {
        match s.query(oid) {
            Ok(b) if b.len() >= 4 => {
                let v = u32::from_le_bytes(b[..4].try_into().unwrap());
                println!("  {label} = {v}");
            }
            Ok(b) => println!("  {label} = ?? ({} bytes)", b.len()),
            Err(e) => println!("  {label} query failed: {e:#}"),
        }
    };
    println!("\n--- device counters ---");
    print_u32("media_connect_status", rndis_mac::rndis::OID_GEN_MEDIA_CONNECT_STATUS);
    print_u32("rcv_ok", rndis_mac::rndis::OID_GEN_RCV_OK);
    print_u32("rcv_error", rndis_mac::rndis::OID_GEN_RCV_ERROR);
    print_u32("xmit_ok", rndis_mac::rndis::OID_GEN_XMIT_OK);
    print_u32("xmit_error", rndis_mac::rndis::OID_GEN_XMIT_ERROR);
    Ok(())
}

fn build_arp_request(src_mac: [u8; 6], src_ip: [u8; 4], tgt_ip: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    // Ethernet
    f.extend_from_slice(&[0xff; 6]); // dst broadcast
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x06]); // ethertype ARP
    // ARP
    f.extend_from_slice(&[0x00, 0x01]); // htype ethernet
    f.extend_from_slice(&[0x08, 0x00]); // ptype IPv4
    f.push(6); // hlen
    f.push(4); // plen
    f.extend_from_slice(&[0x00, 0x01]); // op request
    f.extend_from_slice(&src_mac); // sender hw
    f.extend_from_slice(&src_ip); // sender proto
    f.extend_from_slice(&[0; 6]); // target hw (unknown)
    f.extend_from_slice(&tgt_ip); // target proto
    f
}

/// Build an Ethernet+IPv6+ICMPv6 Neighbor Solicitation for `tgt`. Source IPv6
/// is the unspecified address (::). Destination is the solicited-node multicast
/// for tgt: ff02::1:ffXX:XXXX from the last 24 bits.
fn build_ipv6_ns(src_mac: [u8; 6], tgt: &[u8; 16]) -> Vec<u8> {
    // Solicited-node multicast: ff02::1:ff + last 3 bytes of tgt
    let mut dst6 = [0u8; 16];
    dst6[0] = 0xff;
    dst6[1] = 0x02;
    dst6[11] = 0x01;
    dst6[12] = 0xff;
    dst6[13] = tgt[13];
    dst6[14] = tgt[14];
    dst6[15] = tgt[15];
    // Multicast Ethernet dst: 33:33: + last 4 bytes of dst6
    let dst_mac = [0x33, 0x33, dst6[12], dst6[13], dst6[14], dst6[15]];

    // ICMPv6 NS: type 135, code 0, checksum, reserved 4B, target addr 16B,
    // option (source link-layer address): type 1, len 1 (8B), src_mac (6B)
    let mut icmp = Vec::new();
    icmp.push(135);
    icmp.push(0);
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&[0, 0, 0, 0]);
    icmp.extend_from_slice(tgt);
    icmp.push(1); // option type
    icmp.push(1); // option len in 8-byte units
    icmp.extend_from_slice(&src_mac);
    let icmp_len = icmp.len();

    // Pseudo-header for checksum: src(16) + dst(16) + len(4) + zero(3) + nh(1)
    let src6 = [0u8; 16];
    let mut psh = Vec::new();
    psh.extend_from_slice(&src6);
    psh.extend_from_slice(&dst6);
    psh.extend_from_slice(&(icmp_len as u32).to_be_bytes());
    psh.extend_from_slice(&[0, 0, 0, 58]); // next header ICMPv6
    psh.extend_from_slice(&icmp);
    let cks = inet_checksum(&psh);
    icmp[2] = (cks >> 8) as u8;
    icmp[3] = cks as u8;

    // IPv6 header
    let mut ip = Vec::new();
    ip.extend_from_slice(&[0x60, 0, 0, 0]); // version 6
    ip.extend_from_slice(&(icmp_len as u16).to_be_bytes()); // payload length
    ip.push(58); // next header ICMPv6
    ip.push(255); // hop limit
    ip.extend_from_slice(&src6);
    ip.extend_from_slice(&dst6);
    ip.extend_from_slice(&icmp);

    // Ethernet
    let mut f = Vec::new();
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x86, 0xDD]);
    f.extend_from_slice(&ip);
    f
}

fn inet_checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    if i < buf.len() {
        sum += (buf[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn describe(f: &[u8]) {
    if f.len() < 14 {
        println!("[runt {}]", f.len());
        return;
    }
    let dst = &f[0..6];
    let src = &f[6..12];
    let et = u16::from_be_bytes([f[12], f[13]]);
    print!(
        "  {:>4}B  {:02x}{:02x}{:02x}{:02x}{:02x}{:02x} -> {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}  et=0x{:04x}",
        f.len(),
        src[0], src[1], src[2], src[3], src[4], src[5],
        dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
        et,
    );
    match et {
        0x0806 if f.len() >= 14 + 28 => {
            let p = &f[14..];
            let op = u16::from_be_bytes([p[6], p[7]]);
            let spa = &p[14..18];
            let tpa = &p[24..28];
            println!(
                "  ARP op={op} {}.{}.{}.{} tells {}.{}.{}.{}",
                spa[0], spa[1], spa[2], spa[3], tpa[0], tpa[1], tpa[2], tpa[3]
            );
        }
        0x0800 if f.len() >= 14 + 20 => {
            let p = &f[14..];
            let proto = p[9];
            let s = &p[12..16];
            let d = &p[16..20];
            println!(
                "  IPv4 proto={proto} {}.{}.{}.{} -> {}.{}.{}.{}",
                s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]
            );
        }
        0x86DD => println!("  IPv6"),
        _ => println!(),
    }
}
