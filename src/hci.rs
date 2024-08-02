use std::fmt::{Debug, Write};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use bytes::Buf;

/// data format from: Bluetooth core specification 5.4 Vol 4: Host Controller Interface Part E Host Controller Interface Functional Specification Hci Data Formats

/// - All values are in binary and hexadecimal little-endian formats unless otherwise noted.
/// - In addition, all parameters which can have negative values shall use two's complement when specifying values.
/// - Unless noted otherwise, the order of parameters in an HCI Command packet or HCI Event packet is the order the parameters are listed in the command or event.
///```
/// --------------------------
/// | opcode 16 bit          |
/// --------------------------
/// | parameter total length |
/// | 8 bit                  |
/// --------------------------
/// | parameter 0            |
/// --------------------------
/// | parameter 1            |
/// --------------------------
/// | ...                    |
/// --------------------------
/// | parameter n            |
/// --------------------------
///```
#[derive(Debug)]
pub struct Command<'a> {
    pub opcode: Opcode,
    /// Lengths of all of the parameters contained in this packet measured in octets. (N.B.: total length of parameters, not number of parameters)
    pub params_len: u8,
    /// Each command has a specific number of parameters associated with it. These parameters and the size of each of the parameters are defined for each command. Each parameter is an integer number of octets in size.
    pub params: &'a [u8],
}

impl<'a> Command<'a> {
    const PARAMS_START_BYTE: usize = 3;

    pub fn from(data: &'a mut [u8]) -> Self {
        let mut reader = data.reader();
        let opcode = Opcode(reader.read_u16::<LittleEndian>().unwrap());
        let params_len = reader.read_u8().unwrap();
        let params = &data[Self::PARAMS_START_BYTE..];

        Self {
            opcode,
            params_len,
            params,
        }
    }
}

/// Opcode has two part: lower 10 bit is OCF, high 6 bit is OGF
/// OGF Range (6 bits): 0x00 to 0x3F (0x3F reserved for vendor-specific debug commands)
/// OCF Range (10 bits): 0x0000 to 0x03FF
#[derive(Clone, Copy)]
pub struct Opcode(u16);

impl Debug for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Opcode(ogf: 0x{:X}, ocf: 0x{:X})", self.ogf(), self.ocf())
    }
}

impl Opcode {
    pub fn ocf(&self) -> u16 {
        self.0 & 0x3FF
    }

    pub fn ogf(&self) -> u8 {
        (self.0 >> 10) as u8
    }
}

/// hci event
pub enum Event {}
