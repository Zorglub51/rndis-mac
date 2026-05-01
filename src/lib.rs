//! RNDIS protocol primitives. Spec: Microsoft Remote NDIS USB Devices.
//!
//! Wire format is little-endian 32-bit fields. Every control message starts
//! with `MessageType` + `MessageLength`. Replies are correlated to requests
//! by an opaque `RequestId` we generate.

pub mod rndis;
pub mod session;
pub mod utun;
