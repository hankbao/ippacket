#![allow(dead_code)]

use std::fmt;
use std::io;

use byteorder::NetworkEndian;

use crate::bytes::{Bytes, Checksum};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum IcmpType4 {
    EchoReply,
    DestinationUnreachable,
    SourceQuench,
    Redirect,
    EchoRequest,
    TimeExceeded,
    ParameterProblem,
    TimestampRequest,
    TimestampReply,
    InformationRequest,
    InformationReply,
    AddressMaskRequest,
    AddressMaskReply,
    Unknown(u8),
}

impl IcmpType4 {
    pub fn new(raw: u8) -> Self {
        match raw {
            0 => IcmpType4::EchoReply,
            3 => IcmpType4::DestinationUnreachable,
            4 => IcmpType4::SourceQuench,
            5 => IcmpType4::Redirect,
            8 => IcmpType4::EchoRequest,
            11 => IcmpType4::TimeExceeded,
            12 => IcmpType4::ParameterProblem,
            13 => IcmpType4::TimestampRequest,
            14 => IcmpType4::TimestampReply,
            15 => IcmpType4::InformationRequest,
            16 => IcmpType4::InformationReply,
            17 => IcmpType4::AddressMaskRequest,
            18 => IcmpType4::AddressMaskReply,
            _ => IcmpType4::Unknown(raw),
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            IcmpType4::EchoReply => 0,
            IcmpType4::DestinationUnreachable => 3,
            IcmpType4::SourceQuench => 4,
            IcmpType4::Redirect => 5,
            IcmpType4::EchoRequest => 8,
            IcmpType4::TimeExceeded => 11,
            IcmpType4::ParameterProblem => 12,
            IcmpType4::TimestampRequest => 13,
            IcmpType4::TimestampReply => 14,
            IcmpType4::InformationRequest => 15,
            IcmpType4::InformationReply => 16,
            IcmpType4::AddressMaskRequest => 17,
            IcmpType4::AddressMaskReply => 18,
            IcmpType4::Unknown(raw) => *raw,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum IcmpType6 {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest,
    EchoReply,
    MulticastListenerQuery,
    MulticastListenerReport,
    MulticastListenerDone,
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation,
    NeighborAdvertisement,
    RedirectMessage,
    RouterRenumbering,
    IcmpNodeInformationQuery,
    IcmpNodeInformationResponse,
    InverseNeighborDiscoverySolicitation,
    InverseNeighborDiscoveryAdvertisement,
    MulticastListenerDiscovery,
    HomeAgentAddressDiscoveryRequest,
    HomeAgentAddressDiscoveryReply,
    MobilePrefixSolicitation,
    MobilePrefixAdvertisement,
    CertificationPathSolicitation,
    CertificationPathAdvertisement,
    MulticastRouterAdvertisement,
    MulticastRouterSolicitation,
    MulticastRouterTermination,
    RPLControlMessage,
    Unknown(u8),
}

impl IcmpType6 {
    pub fn new(raw: u8) -> Self {
        match raw {
            1 => IcmpType6::DestinationUnreachable,
            2 => IcmpType6::PacketTooBig,
            3 => IcmpType6::TimeExceeded,
            4 => IcmpType6::ParameterProblem,
            128 => IcmpType6::EchoRequest,
            129 => IcmpType6::EchoReply,
            130 => IcmpType6::MulticastListenerQuery,
            131 => IcmpType6::MulticastListenerReport,
            132 => IcmpType6::MulticastListenerDone,
            133 => IcmpType6::RouterSolicitation,
            134 => IcmpType6::RouterAdvertisement,
            135 => IcmpType6::NeighborSolicitation,
            136 => IcmpType6::NeighborAdvertisement,
            137 => IcmpType6::RedirectMessage,
            138 => IcmpType6::RouterRenumbering,
            139 => IcmpType6::IcmpNodeInformationQuery,
            140 => IcmpType6::IcmpNodeInformationResponse,
            141 => IcmpType6::InverseNeighborDiscoverySolicitation,
            142 => IcmpType6::InverseNeighborDiscoveryAdvertisement,
            143 => IcmpType6::MulticastListenerDiscovery,
            144 => IcmpType6::HomeAgentAddressDiscoveryRequest,
            145 => IcmpType6::HomeAgentAddressDiscoveryReply,
            146 => IcmpType6::MobilePrefixSolicitation,
            147 => IcmpType6::MobilePrefixAdvertisement,
            148 => IcmpType6::CertificationPathSolicitation,
            149 => IcmpType6::CertificationPathAdvertisement,
            151 => IcmpType6::MulticastRouterAdvertisement,
            152 => IcmpType6::MulticastRouterSolicitation,
            153 => IcmpType6::MulticastRouterTermination,
            155 => IcmpType6::RPLControlMessage,
            _ => IcmpType6::Unknown(raw),
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            IcmpType6::DestinationUnreachable => 1,
            IcmpType6::PacketTooBig => 2,
            IcmpType6::TimeExceeded => 3,
            IcmpType6::ParameterProblem => 4,
            IcmpType6::EchoRequest => 128,
            IcmpType6::EchoReply => 129,
            IcmpType6::MulticastListenerQuery => 130,
            IcmpType6::MulticastListenerReport => 131,
            IcmpType6::MulticastListenerDone => 132,
            IcmpType6::RouterSolicitation => 133,
            IcmpType6::RouterAdvertisement => 134,
            IcmpType6::NeighborSolicitation => 135,
            IcmpType6::NeighborAdvertisement => 136,
            IcmpType6::RedirectMessage => 137,
            IcmpType6::RouterRenumbering => 138,
            IcmpType6::IcmpNodeInformationQuery => 139,
            IcmpType6::IcmpNodeInformationResponse => 140,
            IcmpType6::InverseNeighborDiscoverySolicitation => 141,
            IcmpType6::InverseNeighborDiscoveryAdvertisement => 142,
            IcmpType6::MulticastListenerDiscovery => 143,
            IcmpType6::HomeAgentAddressDiscoveryRequest => 144,
            IcmpType6::HomeAgentAddressDiscoveryReply => 145,
            IcmpType6::MobilePrefixSolicitation => 146,
            IcmpType6::MobilePrefixAdvertisement => 147,
            IcmpType6::CertificationPathSolicitation => 148,
            IcmpType6::CertificationPathAdvertisement => 149,
            IcmpType6::MulticastRouterAdvertisement => 151,
            IcmpType6::MulticastRouterSolicitation => 152,
            IcmpType6::MulticastRouterTermination => 153,
            IcmpType6::RPLControlMessage => 155,
            IcmpType6::Unknown(raw) => *raw,
        }
    }
}

#[derive(Clone)]
pub struct IcmpHeader(Bytes);

impl IcmpHeader {
    pub fn with_bytes(bytes: Bytes) -> io::Result<(IcmpHeader, Bytes)> {
        let mut header = IcmpHeader(bytes);
        let remaining = try_split!(header.0, IcmpHeader::len());
        Ok((header, remaining))
    }

    pub fn len() -> usize {
        8
    }

    pub fn icmp_type(&self) -> u8 {
        self.0.read_u8(0).unwrap()
    }

    pub fn icmp_code(&self) -> u8 {
        self.0.read_u8(1).unwrap()
    }

    pub fn id(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(4).unwrap()
    }

    pub fn seq(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(6).unwrap()
    }

    fn checksum(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(2).unwrap()
    }

    pub fn checksum_valid<V: Iterator<Item = u16>>(&self, data: V) -> bool {
        self.checksum() == self.calculated_checksum(data)
    }

    /// This function should only be used to calculate the checksum for ICMPv4 packets
    /// as it does not include the pseudo-header for ICMPv6 packets.
    /// Usually, the OS will calculate the checksum for ICMPv6 packets.
    pub fn calculated_checksum<V: Iterator<Item = u16>>(&self, data: V) -> u16 {
        self.0
            .slice(0, 2)
            .pair_iter()
            .chain(self.0.slice(4, IcmpHeader::len()).pair_iter())
            .chain(data)
            .checksum()
    }

    pub fn set_icmp_type(&mut self, icmp_type: u8) {
        self.0.write_u8(0, icmp_type).unwrap();
    }

    pub fn set_icmp_code(&mut self, icmp_code: u8) {
        self.0.write_u8(1, icmp_code).unwrap();
    }

    pub fn set_id(&mut self, id: u16) {
        self.0.write_u16::<NetworkEndian>(4, id).unwrap();
    }

    pub fn set_seq(&mut self, seq: u16) {
        self.0.write_u16::<NetworkEndian>(6, seq).unwrap();
    }

    fn set_checksum(&mut self, checksum: u16) {
        self.0.write_u16::<NetworkEndian>(2, checksum).unwrap();
    }

    /// This function should only be used to calculate the checksum for ICMPv4 packets
    /// as it does not include the pseudo-header for ICMPv6 packets.
    /// Usually, the OS will calculate the checksum for ICMPv6 packets.
    pub fn calculate_checksum<V: Iterator<Item = u16>>(&mut self, data: V) {
        let checksum = self.calculated_checksum(data);
        self.set_checksum(checksum);
    }
}

impl fmt::Debug for IcmpHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if self.icmp_type() == IcmpType4::EchoRequest.value()
            || self.icmp_type() == IcmpType4::EchoReply.value()
        {
            fmt.debug_struct("IcmpHeader")
                .field("icmp_type", &self.icmp_type())
                .field("icmp_code", &self.icmp_code())
                .field("id", &self.id())
                .field("seq", &self.seq())
                .finish()
        } else {
            fmt.debug_struct("IcmpHeader")
                .field("icmp_type", &self.icmp_type())
                .field("icmp_code", &self.icmp_code())
                .finish()
        }
    }
}
