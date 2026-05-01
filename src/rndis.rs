//! Minimal RNDIS message encoder/decoder. Only the messages we actually use.

use anyhow::{anyhow, bail, Result};

pub const MSG_PACKET: u32 = 0x0000_0001;
pub const MSG_INIT: u32 = 0x0000_0002;
pub const MSG_INIT_C: u32 = 0x8000_0002;
pub const MSG_HALT: u32 = 0x0000_0003;
pub const MSG_QUERY: u32 = 0x0000_0004;
pub const MSG_QUERY_C: u32 = 0x8000_0004;
pub const MSG_SET: u32 = 0x0000_0005;
pub const MSG_SET_C: u32 = 0x8000_0005;
pub const MSG_RESET_C: u32 = 0x8000_0006;
pub const MSG_INDICATE: u32 = 0x0000_0007;
pub const MSG_KEEPALIVE: u32 = 0x0000_0008;
pub const MSG_KEEPALIVE_C: u32 = 0x8000_0008;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;

// OIDs we care about
pub const OID_GEN_MAXIMUM_FRAME_SIZE: u32 = 0x0001_0106;
pub const OID_GEN_LINK_SPEED: u32 = 0x0001_0107;
pub const OID_GEN_MEDIA_CONNECT_STATUS: u32 = 0x0001_0114;
pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001_010E;
pub const OID_802_3_PERMANENT_ADDRESS: u32 = 0x0101_0101;
pub const OID_802_3_CURRENT_ADDRESS: u32 = 0x0101_0102;
pub const OID_GEN_XMIT_OK: u32 = 0x0002_0101;
pub const OID_GEN_RCV_OK: u32 = 0x0002_0102;
pub const OID_GEN_XMIT_ERROR: u32 = 0x0002_0103;
pub const OID_GEN_RCV_ERROR: u32 = 0x0002_0104;

// Packet-filter bits
pub const FILTER_DIRECTED: u32 = 0x0000_0001;
pub const FILTER_MULTICAST: u32 = 0x0000_0002;
pub const FILTER_ALL_MULTICAST: u32 = 0x0000_0004;
pub const FILTER_BROADCAST: u32 = 0x0000_0008;
pub const FILTER_PROMISCUOUS: u32 = 0x0000_0020;

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn build_init(request_id: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    put_u32(&mut b, MSG_INIT);
    put_u32(&mut b, 24); // total length
    put_u32(&mut b, request_id);
    put_u32(&mut b, 1); // major version
    put_u32(&mut b, 0); // minor version
    put_u32(&mut b, 0x4000); // max transfer size we accept (16K)
    b
}

pub fn build_query(request_id: u32, oid: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(28);
    put_u32(&mut b, MSG_QUERY);
    put_u32(&mut b, 28);
    put_u32(&mut b, request_id);
    put_u32(&mut b, oid);
    put_u32(&mut b, 0); // info buffer length
    put_u32(&mut b, 0); // info buffer offset (from byte 8 of message)
    put_u32(&mut b, 0); // device VC handle (reserved, 0)
    b
}

pub fn build_set(request_id: u32, oid: u32, value: &[u8]) -> Vec<u8> {
    let header_len = 28u32;
    let total = header_len + value.len() as u32;
    let mut b = Vec::with_capacity(total as usize);
    put_u32(&mut b, MSG_SET);
    put_u32(&mut b, total);
    put_u32(&mut b, request_id);
    put_u32(&mut b, oid);
    put_u32(&mut b, value.len() as u32); // info buffer length
    put_u32(&mut b, header_len - 8); // info buffer offset (relative to byte 8)
    put_u32(&mut b, 0); // device VC handle
    b.extend_from_slice(value);
    b
}

pub fn build_keepalive(request_id: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(12);
    put_u32(&mut b, MSG_KEEPALIVE);
    put_u32(&mut b, 12);
    put_u32(&mut b, request_id);
    b
}

#[derive(Debug)]
pub struct InitComplete {
    pub request_id: u32,
    pub status: u32,
    pub max_transfer_size: u32,
    pub packet_alignment_factor: u32, // log2
}

pub fn parse_init_complete(buf: &[u8]) -> Result<InitComplete> {
    if buf.len() < 48 {
        bail!("init_cmplt too short: {}", buf.len());
    }
    let mt = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if mt != MSG_INIT_C {
        bail!("expected INIT_C 0x{:08x}, got 0x{:08x}", MSG_INIT_C, mt);
    }
    Ok(InitComplete {
        request_id: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        status: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
        max_transfer_size: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
        packet_alignment_factor: u32::from_le_bytes(buf[40..44].try_into().unwrap()),
    })
}

#[derive(Debug)]
pub struct QueryComplete<'a> {
    pub request_id: u32,
    pub status: u32,
    pub info: &'a [u8],
}

pub fn parse_query_complete(buf: &[u8]) -> Result<QueryComplete<'_>> {
    if buf.len() < 24 {
        bail!("query_cmplt too short: {}", buf.len());
    }
    let mt = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if mt != MSG_QUERY_C {
        bail!("expected QUERY_C 0x{:08x}, got 0x{:08x}", MSG_QUERY_C, mt);
    }
    let req = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let status = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let info_len = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    let info_off = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
    // offset is from byte 8 of the message
    let start = 8 + info_off;
    let end = start + info_len;
    let info = buf
        .get(start..end)
        .ok_or_else(|| anyhow!("info buffer out of range: {start}..{end} of {}", buf.len()))?;
    Ok(QueryComplete { request_id: req, status, info })
}

#[derive(Debug)]
pub struct SetComplete {
    pub request_id: u32,
    pub status: u32,
}

pub fn parse_set_complete(buf: &[u8]) -> Result<SetComplete> {
    if buf.len() < 16 {
        bail!("set_cmplt too short: {}", buf.len());
    }
    let mt = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if mt != MSG_SET_C {
        bail!("expected SET_C 0x{:08x}, got 0x{:08x}", MSG_SET_C, mt);
    }
    Ok(SetComplete {
        request_id: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        status: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
    })
}

/// Wrap a single Ethernet frame in a RNDIS_PACKET_MSG.
pub fn build_packet(eth: &[u8]) -> Vec<u8> {
    let header = 44u32;
    let total = header + eth.len() as u32;
    let mut b = Vec::with_capacity(total as usize);
    put_u32(&mut b, MSG_PACKET);
    put_u32(&mut b, total);
    put_u32(&mut b, header - 8); // data offset (rel to byte 8)
    put_u32(&mut b, eth.len() as u32); // data length
    // OOB data offset, length, num elements; per-packet info offset, length; reserved 2x
    for _ in 0..7 {
        put_u32(&mut b, 0);
    }
    b.extend_from_slice(eth);
    b
}

/// Iterate Ethernet payloads out of a bulk-IN buffer (which may carry several
/// concatenated RNDIS_PACKET_MSGs).
pub fn iter_packets(buf: &[u8]) -> PacketIter<'_> {
    PacketIter { buf, pos: 0 }
}

pub struct PacketIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = Result<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 8 > self.buf.len() {
            return None;
        }
        let mt = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        let len =
            u32::from_le_bytes(self.buf[self.pos + 4..self.pos + 8].try_into().unwrap()) as usize;
        if len < 8 || self.pos + len > self.buf.len() {
            return Some(Err(anyhow!("malformed RNDIS frame: type=0x{mt:08x} len={len}")));
        }
        let msg = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        if mt != MSG_PACKET {
            // Not a data packet (e.g. INDICATE_STATUS interleaved); skip.
            return self.next();
        }
        if msg.len() < 44 {
            return Some(Err(anyhow!("PACKET_MSG too short: {}", msg.len())));
        }
        let data_off = u32::from_le_bytes(msg[8..12].try_into().unwrap()) as usize + 8;
        let data_len = u32::from_le_bytes(msg[12..16].try_into().unwrap()) as usize;
        let end = data_off + data_len;
        if end > msg.len() {
            return Some(Err(anyhow!("PACKET payload overflows frame")));
        }
        Some(Ok(&msg[data_off..end]))
    }
}
