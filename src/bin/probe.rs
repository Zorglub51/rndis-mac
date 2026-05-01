//! Milestone 1: open the hakchi/classic device and dump its descriptors so
//! we know exactly which interfaces and endpoints to use for RNDIS.
//!
//! Expected layout for an RNDIS gadget:
//!   - One IAD covering two interfaces (class E0/01/03 + 0A/00/00).
//!   - Communication interface: 1 interrupt-IN endpoint (notifications).
//!   - Data interface: 1 bulk-IN + 1 bulk-OUT endpoint.

use anyhow::{anyhow, Result};

const VID: u16 = 0x04E8;
const PID: u16 = 0x6863;

fn main() -> Result<()> {
    let info = nusb::list_devices()?
        .find(|d| d.vendor_id() == VID && d.product_id() == PID)
        .ok_or_else(|| anyhow!("hakchi/classic ({VID:04x}:{PID:04x}) not found"))?;

    println!(
        "device: {:04x}:{:04x}  {} / {}  serial={}",
        info.vendor_id(),
        info.product_id(),
        info.manufacturer_string().unwrap_or("?"),
        info.product_string().unwrap_or("?"),
        info.serial_number().unwrap_or("?"),
    );

    let dev = info.open()?;
    let cfg = dev
        .active_configuration()
        .or_else(|_| dev.configurations().next().ok_or_else(|| anyhow!("no config")))?;

    println!(
        "\nconfig #{}  ({} interface(s))",
        cfg.configuration_value(),
        cfg.interfaces().count()
    );

    for iface in cfg.interfaces() {
        for alt in iface.alt_settings() {
            println!(
                "  iface {} alt {}  class={:02x}/{:02x}/{:02x}  endpoints={}",
                alt.interface_number(),
                alt.alternate_setting(),
                alt.class(),
                alt.subclass(),
                alt.protocol(),
                alt.endpoints().count(),
            );
            for ep in alt.endpoints() {
                println!(
                    "      ep 0x{:02x}  {:?} {:?}  max_packet={}",
                    ep.address(),
                    ep.transfer_type(),
                    ep.direction(),
                    ep.max_packet_size(),
                );
            }
            // Walk class-specific descriptors (CDC functional descriptors live here).
            for d in alt.descriptors() {
                if matches!(d.descriptor_type(), 0x24 | 0x25) {
                    println!("      cs-desc type=0x{:02x} bytes={:02x?}", d.descriptor_type(), &d[..]);
                }
            }
        }
    }
    Ok(())
}
