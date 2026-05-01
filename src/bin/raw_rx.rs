//! Submit a bulk-IN, dump raw bytes if anything arrives. Bypasses RNDIS framing
//! parsing entirely, so we'll see whatever the device sends regardless of form.

use anyhow::Result;
use nusb::transfer::RequestBuffer;
use rndis_mac::session::Session;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() -> Result<()> {
    let s = Arc::new(Session::open(0x04E8, 0x6863)?);
    println!("session up");

    let s_rx = Arc::clone(&s);
    thread::spawn(move || {
        let q = s_rx.data.bulk_in_queue(0x81);
        let mut q = q;
        for _ in 0..16 {
            q.submit(RequestBuffer::new(16384));
        }
        loop {
            let c = futures_lite::future::block_on(q.next_complete());
            match c.status {
                Ok(()) => {
                    let buf = c.data;
                    println!("[bulk-in] {} bytes:", buf.len());
                    for chunk in buf.chunks(32) {
                        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
                        println!("  {hex}");
                    }
                    q.submit(RequestBuffer::new(16384));
                }
                Err(e) => {
                    eprintln!("[bulk-in] error {e:?}");
                    return;
                }
            }
        }
    });

    // Send a unicast ARP to the device's MAC asking for 169.254.13.37 (us)
    // — this should at least make the kernel notice and update its ARP cache.
    // Then send a broadcast ARP for several link-local /16 candidates.
    let host_mac = [0x02, 0, 0, 0, 0, 0x37];
    let host_ip = [169, 254, 13, 37];

    // ARP gratuitous from us announcing our IP — should trigger nothing but
    // is a useful "I'm here" beacon.
    let mut grat = build_arp(host_mac, [0xff; 6], host_ip, host_ip, 1);
    s.send_eth(&grat)?;
    println!("sent gratuitous ARP for 169.254.13.37");
    grat[20] = 0x00;
    grat[21] = 0x02; // op = reply
    s.send_eth(&grat)?;
    println!("sent gratuitous ARP reply");

    // Sweep broader link-local space (sample, not full /16).
    for sub in [13u8, 0, 1, 2, 100, 137, 169, 254] {
        for host in [1u8, 2, 36, 38, 100, 200] {
            let frame = build_arp(host_mac, [0xff; 6], host_ip, [169, 254, sub, host], 1);
            s.send_eth(&frame)?;
            thread::sleep(Duration::from_millis(8));
        }
    }
    println!("sent sweep");

    thread::sleep(Duration::from_secs(8));
    println!("\n-- counters --");
    for (name, oid) in [
        ("rcv_ok", rndis_mac::rndis::OID_GEN_RCV_OK),
        ("rcv_err", rndis_mac::rndis::OID_GEN_RCV_ERROR),
        ("xmit_ok", rndis_mac::rndis::OID_GEN_XMIT_OK),
        ("xmit_err", rndis_mac::rndis::OID_GEN_XMIT_ERROR),
    ] {
        if let Ok(b) = s.query(oid) {
            if b.len() >= 4 {
                let v = u32::from_le_bytes(b[..4].try_into().unwrap());
                println!("  {name} = {v}");
            }
        }
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
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&tgt_ip);
    f
}
