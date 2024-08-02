use byteorder::{BigEndian, ReadBytesExt};
use num_enum::TryFromPrimitive;
use std::{
    fmt::Display,
    io::{self, Read},
};

use crate::hci::Command;

pub mod hci;

///```
/// -----------------------
/// | header              |
/// -----------------------
/// | packet record nbr 1 |
/// -----------------------
/// | packet record nbr 2 |
/// -----------------------
/// | ...                 |
/// -----------------------
/// | packet record nbr n |
/// -----------------------
///```
#[derive(Debug)]
pub struct Btsnoop {
    pub header: Header,
    pub packets: Vec<Packet>,
}

/// ```
/// ----------------------------------------
/// | identification pattern 64 bit        |
/// ----------------------------------------
/// | version number 32 bit                |
/// ----------------------------------------
/// | datalink type 32 bit                 |
/// ----------------------------------------
/// ```
#[derive(Debug)]
pub struct Header {
    // This is the ASCII string "btsnoop" followed by one null octets, must be: 62 74 73 6E 6F 6F 70 00
    pub identification_pattern: IdentificationPattern,
    pub version: u32,
    pub datalink_type: DatalinkType,
}

/// | Datalink Type | Code |
/// | --- | --- |
/// | Reserved        | 0 - 1000 |
/// | Un-encapsulated HCI (H1) | 1001 |
/// | HCI UART (H4) | 1002 |
/// | HCI BSCP | 1003 |
/// | HCI Serial (H5) | 1004 |
/// | Unassigned | 1005 - 4294967295 |
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DatalinkType {
    Reserved(u32),
    UnencapsulatedHci = 1001,
    /// aka U4
    Uart,
    Bscp,
    /// aka Three Wire
    Serial,
    /// when unknown save the raw value
    Unassigned(u32),
}

/// 64 bit 62 74 73 6E 6F 6F 70 00 (aka. b'btsnoop\0')
#[derive(Debug)]
pub struct IdentificationPattern;

/// ```
/// --------------------------
/// | original length        |
/// | 32 bit
/// --------------------------
/// | included length        |
/// | 32 bit
/// --------------------------
/// | packet flags           |
/// | 32 bit
/// --------------------------
/// | cumulative drops       |
/// | 32 bit
/// --------------------------
/// | timestamp microseconds |
/// | 64 bit
/// --------------------------
/// | packet data            |
/// --------------------------
/// ```
#[derive(Debug)]
pub struct Packet {
    pub description: PacketDescription,
    pub data: PacketData,
}

#[derive(Debug)]
pub struct PacketDescription {
    /// A 32-bit unsigned integer representing the length in octets of the captured packet as received via a network.
    pub original_length: u32,
    /// A 32-bit unsigned integer representing the length of the Packet Data field. This is the number of octets of the captured packet that are included in this packet record. If the received packet was truncated, the Included Length field is less than the Original Length field.
    pub included_length: u32,
    /// A 32-bit flag
    pub flags: PacketFlags,
    /// A 32-bit unsigned integer representing the number of packets that were lost by the system that created the packet file between the first packet record in the file and this one. Packets may be lost because of insufficient resources in the capturing system, or for other reasons.
    pub cumulative_drops: u32,
    pub timestamp: i64,
}

/// Variable-length field holding the packet that was captured, beginning with its datalink header. The Datalink Type field of the file header can be used to determine how to decode the datalink header. The length of the Packet Data field is given in the Included Length field.
#[derive(Debug, Clone)]
pub struct PacketData(pub Vec<u8>);

/// | Bit No. | Definition |
/// | --- | --- |
/// | 0 | Direction flag 0 = Sent, 1 = Received |
/// | 1 | Command flag 0 = Data, 1 = Command/Event |
/// | 2 - 31 | Reserved |
#[derive(Debug)]
pub struct PacketFlags(pub u32);

#[derive(Debug)]
pub enum DirectionFlag {
    Sent,
    Received,
}

// bit 1
/// Some Datalink Types already encode some or all of this information within the Packet Data.
/// With these Datalink Types, these flags should be treated as informational only,
/// and the value in the Packet Data should take precedence.
#[derive(Debug)]
pub enum CommandFlag {
    Data,
    CommandOrEvnet,
}

impl Btsnoop {
    pub fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        let header = Header::parse(reader)?;
        let mut packets = vec![];
        loop {
            let packet = Packet::parse(reader);
            match packet {
                Ok(packet) => packets.push(packet),
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }

        Ok(Self { header, packets })
    }
}

impl Header {
    pub fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut id_pat = [0u8; 8];
        reader.read_exact(&mut id_pat)?;
        let identification_pattern: IdentificationPattern = id_pat.try_into()?;
        let version = reader.read_u32::<BigEndian>()?;
        let datalink_type = reader.read_u32::<BigEndian>()?;
        let datalink_type: DatalinkType = datalink_type.into();

        Ok(Self {
            identification_pattern,
            version,
            datalink_type,
        })
    }

    pub fn identification_pattern(&self) -> &'static str {
        IdentificationPattern::NAME
    }
}

impl IdentificationPattern {
    pub const NAME: &'static str = "btsnoop";
    pub const IDENTIFICATION_PATTERN: [u8; 8] = [0x62, 0x74, 0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00];
}

impl Display for IdentificationPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(IdentificationPattern::NAME)
    }
}

impl TryFrom<[u8; 8]> for IdentificationPattern {
    type Error = io::Error;

    fn try_from(value: [u8; 8]) -> Result<Self, Self::Error> {
        if value == IdentificationPattern::IDENTIFICATION_PATTERN {
            Ok(Self)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid identification pattern",
            ))
        }
    }
}

impl From<u32> for DatalinkType {
    fn from(value: u32) -> Self {
        match value {
            0..=1000 => DatalinkType::Reserved(value),
            1001 => DatalinkType::UnencapsulatedHci,
            1002 => DatalinkType::Uart,
            1003 => DatalinkType::Bscp,
            1004 => DatalinkType::Serial,
            _ => DatalinkType::Unassigned(value),
        }
    }
}

impl Packet {
    pub fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        let description = PacketDescription::parse(reader)?;
        let mut data = vec![0; description.included_length as usize];
        // let mut data = Vec::with_capacity(description.included_length as usize);
        reader.read_exact(&mut data)?;
        let data = PacketData(data);

        Ok(Self { description, data })
    }
}

impl PacketDescription {
    pub fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        let original_length = reader.read_u32::<BigEndian>()?;
        let included_length = reader.read_u32::<BigEndian>()?;
        let flags = reader.read_u32::<BigEndian>()?;
        let flags = PacketFlags(flags);
        let cumulative_drops = reader.read_u32::<BigEndian>()?;
        let timestamp = reader.read_i64::<BigEndian>()?;
        Ok(PacketDescription {
            original_length,
            included_length,
            flags,
            cumulative_drops,
            timestamp,
        })
    }
}

impl TryFrom<u8> for DirectionFlag {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 1 {
            0 => Ok(DirectionFlag::Sent),
            1 => Ok(DirectionFlag::Received),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid direction flag",
            )),
        }
    }
}

impl TryFrom<u8> for CommandFlag {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match (value >> 1) & 1 {
            0 => Ok(CommandFlag::Data),
            1 => Ok(CommandFlag::CommandOrEvnet),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid command flag",
            )),
        }
    }
}

#[repr(u8)]
#[derive(Debug, TryFromPrimitive)]
pub enum UartPacketType {
    Cmd = 1,
    Acl,
    Sco,
    Evt,
    Iso,
}

#[derive(Debug)]
pub enum UartData<'a> {
    Command(hci::Command<'a>),
    Todos,
}

/// for uart packet, first 8 bit is the packet type
pub fn parse_uart_packet(packet: &mut Packet) -> io::Result<UartData<'_>> {
    let data = &mut packet.data.0;
    if data.is_empty() {
        return Ok(UartData::Todos);
    }
    let tp = data[0];
    use UartPacketType::*;
    let uart_type = UartPacketType::try_from_primitive(tp)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid packet type"))?;
    match uart_type {
        Cmd => {
            let cmd = Command::from(&mut data[1..]);
            Ok(UartData::Command(cmd))
        }
        _ => Ok(UartData::Todos),
    }
}

#[cfg(test)]
mod test {
    use crate::{parse_uart_packet, Btsnoop, UartData};

    #[test]
    fn read_test() {
        let mut f: &[u8] = include_bytes!("../res/btsnoop_hci.cfa");
        // let mut f = include_str!("../res/btsnoop_hci_android.log");
        let mut bs = Btsnoop::parse(&mut f).unwrap();
        let mut count = 0;
        // 0000 0011 0000 1100
        for pkt in &mut bs.packets {
            if count > 1000 {
                break;
            }
            count += 1;
            println!("{:?}", pkt);
            if let Ok(cmd) = parse_uart_packet(pkt) {
                if let UartData::Command(_) = cmd {
                    println!("{:?}", cmd)
                }
            }
        }
    }
}
