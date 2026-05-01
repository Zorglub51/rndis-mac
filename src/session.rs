//! Open a RNDIS device, run the control handshake, and expose simple
//! bulk read/write helpers carrying Ethernet frames.

use crate::rndis;
use anyhow::{anyhow, bail, Context, Result};
use nusb::transfer::{ControlIn, ControlOut, ControlType, Recipient, RequestBuffer};
use nusb::{Device, Interface};
use std::sync::atomic::{AtomicU32, Ordering};

const COMM_IFACE: u8 = 0;
const DATA_IFACE: u8 = 1;
const NOTIFY_EP: u8 = 0x84;
const BULK_IN: u8 = 0x81;
const BULK_OUT: u8 = 0x01;
const BULK_BUF: usize = 16 * 1024;

pub struct Session {
    pub mac: [u8; 6],
    pub mtu: u32,
    _dev: Device,
    pub comm: Interface,
    pub data: Interface,
    next_id: AtomicU32,
}

impl Session {
    pub fn open(vid: u16, pid: u16) -> Result<Self> {
        let info = nusb::list_devices()?
            .find(|d| d.vendor_id() == vid && d.product_id() == pid)
            .ok_or_else(|| anyhow!("device {vid:04x}:{pid:04x} not found"))?;
        let dev = info.open()?;
        let _ = dev.set_configuration(1);
        let comm = dev.claim_interface(COMM_IFACE).context("claim comm iface")?;
        let data = dev.claim_interface(DATA_IFACE).context("claim data iface")?;

        let mut s = Self {
            mac: [0; 6],
            mtu: 1500,
            _dev: dev,
            comm,
            data,
            next_id: AtomicU32::new(1),
        };
        s.handshake()?;
        Ok(s)
    }

    fn next_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn send_command(&self, payload: &[u8]) -> Result<()> {
        futures_lite::future::block_on(self.comm.control_out(ControlOut {
            control_type: ControlType::Class,
            recipient: Recipient::Interface,
            request: 0x00,
            value: 0,
            index: COMM_IFACE as u16,
            data: payload,
        }))
        .into_result()
        .context("SEND_ENCAPSULATED_COMMAND")?;
        Ok(())
    }

    fn get_response(&self) -> Result<Vec<u8>> {
        let r = futures_lite::future::block_on(self.comm.control_in(ControlIn {
            control_type: ControlType::Class,
            recipient: Recipient::Interface,
            request: 0x01,
            value: 0,
            index: COMM_IFACE as u16,
            length: 1025,
        }))
        .into_result()
        .context("GET_ENCAPSULATED_RESPONSE")?;
        Ok(r)
    }

    fn wait_response_available(&self) -> Result<()> {
        let mut q = self.comm.interrupt_in_queue(NOTIFY_EP);
        q.submit(RequestBuffer::new(8));
        let data = futures_lite::future::block_on(q.next_complete())
            .into_result()
            .context("interrupt IN")?;
        if data.len() < 4 {
            bail!("notify too short");
        }
        let kind = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if kind != 0x0000_0001 {
            bail!("unexpected notify 0x{kind:08x}");
        }
        Ok(())
    }

    fn round_trip(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.send_command(msg)?;
        // Drain any unsolicited INDICATE_STATUS frames first.
        loop {
            self.wait_response_available()?;
            let r = self.get_response()?;
            if r.len() >= 4 {
                let mt = u32::from_le_bytes(r[0..4].try_into().unwrap());
                if mt == rndis::MSG_INDICATE {
                    let status = if r.len() >= 12 {
                        u32::from_le_bytes(r[8..12].try_into().unwrap())
                    } else {
                        0
                    };
                    eprintln!("[indicate-status 0x{status:08x}]");
                    continue;
                }
            }
            return Ok(r);
        }
    }

    /// Drain any queued encapsulated responses left over from a prior session.
    fn drain_pending(&self) {
        for _ in 0..4 {
            let r = futures_lite::future::block_on(self.comm.control_in(ControlIn {
                control_type: ControlType::Class,
                recipient: Recipient::Interface,
                request: 0x01,
                value: 0,
                index: COMM_IFACE as u16,
                length: 1025,
            }));
            match r.into_result() {
                Ok(b) if !b.is_empty() => eprintln!("[drained {} bytes]", b.len()),
                _ => return,
            }
        }
    }

    fn handshake(&mut self) -> Result<()> {
        // Reset device's RNDIS state by sending HALT first, then drain.
        let mut halt = Vec::with_capacity(12);
        halt.extend_from_slice(&rndis::MSG_HALT.to_le_bytes());
        halt.extend_from_slice(&12u32.to_le_bytes());
        halt.extend_from_slice(&0u32.to_le_bytes());
        let _ = self.send_command(&halt);
        std::thread::sleep(std::time::Duration::from_millis(50));
        self.drain_pending();

        let init = rndis::build_init(self.next_id());
        let r = self.round_trip(&init)?;
        let ic = rndis::parse_init_complete(&r)?;
        if ic.status != rndis::STATUS_SUCCESS {
            bail!("init failed 0x{:08x}", ic.status);
        }

        let q = rndis::build_query(self.next_id(), rndis::OID_802_3_PERMANENT_ADDRESS);
        let r = self.round_trip(&q)?;
        let qc = rndis::parse_query_complete(&r)?;
        if qc.status != rndis::STATUS_SUCCESS || qc.info.len() < 6 {
            bail!("MAC query failed 0x{:08x}", qc.status);
        }
        self.mac.copy_from_slice(&qc.info[..6]);

        let q = rndis::build_query(self.next_id(), rndis::OID_GEN_MAXIMUM_FRAME_SIZE);
        if let Ok(r) = self.round_trip(&q) {
            if let Ok(qc) = rndis::parse_query_complete(&r) {
                if qc.info.len() >= 4 {
                    self.mtu = u32::from_le_bytes(qc.info[..4].try_into().unwrap());
                }
            }
        }

        let filter = rndis::FILTER_DIRECTED
            | rndis::FILTER_BROADCAST
            | rndis::FILTER_ALL_MULTICAST
            | rndis::FILTER_PROMISCUOUS;
        let s = rndis::build_set(
            self.next_id(),
            rndis::OID_GEN_CURRENT_PACKET_FILTER,
            &filter.to_le_bytes(),
        );
        let r = self.round_trip(&s)?;
        let sc = rndis::parse_set_complete(&r)?;
        if sc.status != rndis::STATUS_SUCCESS {
            bail!("set filter failed 0x{:08x}", sc.status);
        }
        Ok(())
    }

    /// Issue an OID query and return the info buffer.
    pub fn query(&self, oid: u32) -> Result<Vec<u8>> {
        let q = rndis::build_query(self.next_id(), oid);
        let r = self.round_trip(&q)?;
        let qc = rndis::parse_query_complete(&r)?;
        if qc.status != rndis::STATUS_SUCCESS {
            bail!("query 0x{oid:08x} status 0x{:08x}", qc.status);
        }
        Ok(qc.info.to_vec())
    }

    pub fn keepalive(&self) -> Result<()> {
        let k = rndis::build_keepalive(self.next_id());
        let r = self.round_trip(&k)?;
        if r.len() < 16 {
            bail!("short keepalive_cmplt");
        }
        Ok(())
    }

    /// Send one Ethernet frame to the device (wraps in a RNDIS_PACKET_MSG).
    pub fn send_eth(&self, frame: &[u8]) -> Result<()> {
        let pkt = rndis::build_packet(frame);
        futures_lite::future::block_on(self.data.bulk_out(BULK_OUT, pkt))
            .into_result()
            .context("bulk OUT")?;
        Ok(())
    }

    /// Block until at least one bulk-IN buffer arrives, return all Ethernet
    /// payloads it contained.
    pub fn recv_eth(&self) -> Result<Vec<Vec<u8>>> {
        let buf = futures_lite::future::block_on(
            self.data.bulk_in(BULK_IN, RequestBuffer::new(BULK_BUF)),
        )
        .into_result()
        .context("bulk IN")?;
        let mut out = Vec::new();
        for r in rndis::iter_packets(&buf) {
            out.push(r?.to_vec());
        }
        Ok(out)
    }
}
