//! Milestone 2: full RNDIS control handshake.
//!
//! Steps: claim iface 0, INITIALIZE → INIT_CMPLT, QUERY MAC, QUERY link speed,
//! SET packet filter, then loop sending KEEPALIVE every 5 s while reading the
//! interrupt-IN endpoint for "response available" notifications.

use anyhow::{anyhow, bail, Context, Result};
use nusb::transfer::{ControlIn, ControlOut, ControlType, Recipient, RequestBuffer};
use rndis_mac::rndis;
use std::time::Duration;

const VID: u16 = 0x04E8;
const PID: u16 = 0x6863;
const COMM_IFACE: u8 = 0;
const DATA_IFACE: u8 = 1;
const NOTIFY_EP: u8 = 0x84;
const TIMEOUT: Duration = Duration::from_secs(2);

fn send_command(iface: &nusb::Interface, payload: &[u8]) -> Result<()> {
    let r = futures_lite::future::block_on(iface.control_out(ControlOut {
        control_type: ControlType::Class,
        recipient: Recipient::Interface,
        request: 0x00, // SEND_ENCAPSULATED_COMMAND
        value: 0,
        index: COMM_IFACE as u16,
        data: payload,
    }))
    .into_result()
    .context("SEND_ENCAPSULATED_COMMAND")?;
    let _ = r;
    Ok(())
}

fn get_response(iface: &nusb::Interface) -> Result<Vec<u8>> {
    let r = futures_lite::future::block_on(iface.control_in(ControlIn {
        control_type: ControlType::Class,
        recipient: Recipient::Interface,
        request: 0x01, // GET_ENCAPSULATED_RESPONSE
        value: 0,
        index: COMM_IFACE as u16,
        length: 1025,
    }))
    .into_result()
    .context("GET_ENCAPSULATED_RESPONSE")?;
    Ok(r)
}

/// Wait for the device to assert "response available" (0x00000001) on the
/// interrupt endpoint. The notification is two LE u32s: notification + reserved.
fn wait_response_available(iface: &nusb::Interface) -> Result<()> {
    // We claimed iface 0 to address EP 0x84.
    let mut q = iface.interrupt_in_queue(NOTIFY_EP);
    q.submit(RequestBuffer::new(8));
    let completion = futures_lite::future::block_on(q.next_complete());
    let data = completion.into_result().context("interrupt IN")?;
    if data.len() < 4 {
        bail!("notify too short: {}", data.len());
    }
    let kind = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if kind != 0x0000_0001 {
        bail!("unexpected notification kind 0x{kind:08x}");
    }
    Ok(())
}

fn round_trip(iface: &nusb::Interface, req: &[u8]) -> Result<Vec<u8>> {
    send_command(iface, req)?;
    wait_response_available(iface)?;
    get_response(iface)
}

fn main() -> Result<()> {
    let info = nusb::list_devices()?
        .find(|d| d.vendor_id() == VID && d.product_id() == PID)
        .ok_or_else(|| anyhow!("device not found"))?;
    let dev = info.open()?;
    if let Err(e) = dev.set_configuration(1) {
        eprintln!("(set_configuration(1) returned {e:?} — may already be configured)");
    }
    let comm = dev.claim_interface(COMM_IFACE).context("claim comm iface")?;
    let _data = dev.claim_interface(DATA_IFACE).context("claim data iface")?;
    println!("claimed interfaces");

    // 1. INITIALIZE
    let init = rndis::build_init(1);
    let resp = round_trip(&comm, &init)?;
    let init_c = rndis::parse_init_complete(&resp)?;
    println!("INIT_CMPLT: {init_c:?}");
    if init_c.status != rndis::STATUS_SUCCESS {
        bail!("init failed: status=0x{:08x}", init_c.status);
    }

    // 2. QUERY MAC
    let q = rndis::build_query(2, rndis::OID_802_3_PERMANENT_ADDRESS);
    let resp = round_trip(&comm, &q)?;
    let qc = rndis::parse_query_complete(&resp)?;
    if qc.status != rndis::STATUS_SUCCESS {
        bail!("MAC query failed: 0x{:08x}", qc.status);
    }
    let mac = qc.info;
    println!(
        "device MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // 3. QUERY link speed (units of 100 bps)
    let q = rndis::build_query(3, rndis::OID_GEN_LINK_SPEED);
    let resp = round_trip(&comm, &q)?;
    let qc = rndis::parse_query_complete(&resp)?;
    if qc.status == rndis::STATUS_SUCCESS && qc.info.len() >= 4 {
        let s = u32::from_le_bytes(qc.info[..4].try_into().unwrap());
        println!("link speed: {} bps", s as u64 * 100);
    }

    // 4. QUERY max frame size
    let q = rndis::build_query(4, rndis::OID_GEN_MAXIMUM_FRAME_SIZE);
    let resp = round_trip(&comm, &q)?;
    let qc = rndis::parse_query_complete(&resp)?;
    if qc.status == rndis::STATUS_SUCCESS && qc.info.len() >= 4 {
        let s = u32::from_le_bytes(qc.info[..4].try_into().unwrap());
        println!("max frame size: {s} bytes");
    }

    // 5. SET packet filter — directed + broadcast + all-multicast.
    let filter =
        rndis::FILTER_DIRECTED | rndis::FILTER_BROADCAST | rndis::FILTER_ALL_MULTICAST;
    let s = rndis::build_set(5, rndis::OID_GEN_CURRENT_PACKET_FILTER, &filter.to_le_bytes());
    let resp = round_trip(&comm, &s)?;
    let sc = rndis::parse_set_complete(&resp)?;
    if sc.status != rndis::STATUS_SUCCESS {
        bail!("set filter failed: 0x{:08x}", sc.status);
    }
    println!("packet filter set: 0x{filter:08x}");

    // 6. Keepalives forever.
    let mut req_id: u32 = 100;
    loop {
        std::thread::sleep(TIMEOUT);
        req_id += 1;
        let k = rndis::build_keepalive(req_id);
        match round_trip(&comm, &k) {
            Ok(_) => println!("keepalive {req_id} ok"),
            Err(e) => {
                eprintln!("keepalive failed: {e:#}");
                break Ok(());
            }
        }
    }
}
