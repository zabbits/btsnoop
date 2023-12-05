#![allow(dead_code, unused)]

use std::{
    fmt::Display,
    fs::read,
    io::{self, Read},
};

use byteorder::{BigEndian, ReadBytesExt};

#[derive(Debug)]
pub struct Btsnoop {
    pub header: Header,
    pub packets: Vec<Packet>,
}

impl Btsnoop {
    pub fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        let header = Header::parse(reader)?;
        let packet = Packet::parse(reader, Some(header.datalink_type))?;
        let mut packets = vec![];
        loop {
            let packet = Packet::parse(reader, Some(header.datalink_type));
            match packet {
                Ok(packet) => packets.push(packet),
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }

        Ok(Self { header, packets })
    }
}

#[derive(Debug)]
pub struct Header {
    // This is the ASCII string "btsnoop" followed by one null octets, must be: 62 74 73 6E 6F 6F 70 00
    pub identification_pattern: IdentificationPattern,
    pub version: u32,
    pub datalink_type: DatalinkType,
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

#[derive(Debug)]
pub struct IdentificationPattern;

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

#[derive(Debug, Clone, Copy)]
pub enum DatalinkType {
    Reserved,
    UnencapsulatedHci,
    Uart,
    Bscp,
    Serial,
    // when unknown save the raw value
    Unknown(u32),
}

impl From<u32> for DatalinkType {
    fn from(value: u32) -> Self {
        match value {
            0..=1000 => DatalinkType::Reserved,
            1001 => DatalinkType::UnencapsulatedHci,
            1002 => DatalinkType::Uart,
            1003 => DatalinkType::Bscp,
            1004 => DatalinkType::Serial,
            _ => DatalinkType::Unknown(value),
        }
    }
}

#[derive(Debug)]
pub struct Packet {
    description: PacketDescription,
    data: PacketData,
}

impl Packet {
    pub fn parse<R: Read>(reader: &mut R, datalink_type: Option<DatalinkType>) -> io::Result<Self> {
        let description = PacketDescription::parse(reader)?;
        let data = PacketData::parse(reader, description.included_length, datalink_type)?;

        Ok(Self { description, data })
    }
}

#[derive(Debug)]
pub struct PacketDescription {
    original_length: u32,
    included_length: u32,
    flags: PacketFlags,
    cumulative_drops: u32,
    timestamp: i64,
}

impl PacketDescription {
    pub fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        let original_length = reader.read_u32::<BigEndian>()?;
        let included_length = reader.read_u32::<BigEndian>()?;
        let mut flags = [0u8; 4];
        reader.read_exact(&mut flags);
        let flags = flags.try_into()?;
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

#[derive(Debug)]
pub struct PacketFlags {
    direction: DirectionFlag,
    command: CommandFlag,
    // raw data of flags
    raw: u32,
}

impl TryFrom<[u8; 4]> for PacketFlags {
    type Error = io::Error;

    fn try_from(value: [u8; 4]) -> Result<Self, Self::Error> {
        let direction = value[3].try_into()?;
        let command = value[3].try_into()?;
        let raw = u32::from_be_bytes(value);

        Ok(Self {
            direction,
            command,
            raw,
        })
    }
}

// bit 0
#[derive(Debug)]
pub enum DirectionFlag {
    Sent,
    Received,
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

// bit 1
#[derive(Debug)]
pub enum CommandFlag {
    Data,
    CommandOrEvnet,
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

// add more types if we can parse specific data
#[derive(Debug)]
pub enum PacketData {
    // when we can not recogonize the data
    Raw(Vec<u8>),
}

impl PacketData {
    pub fn parse<R: Read>(
        reader: &mut R,
        len: u32,
        datalink_type: Option<DatalinkType>,
    ) -> io::Result<Self> {
        let mut packet_data = vec![0u8; len as usize];
        reader.read_exact(&mut packet_data)?;

        Ok(PacketData::Raw(packet_data))
    }
}

#[cfg(test)]
mod test {
}
