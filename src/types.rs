/// Represents the structure of a TCP header
#[derive(Debug, Clone)]
#[repr(C)]
pub struct TcpHeader {
    /// Source port (16 bits)
    pub source_port: u16,
    /// Destination port (16 bits)
    pub destination_port: u16,
    /// Sequence number (32 bits)
    pub sequence_number: u32,
    /// Acknowledgment number (32 bits)
    pub ack_number: u32,
    /// Data offset (4 bits) - Number of 32-bit words in header
    pub header_length: u8,
    /// Reserved (3 bits)
    pub reserved: u8,
    /// Control flags (9 bits)
    pub flags_cwr: bool, // Congestion Window Reduced
    pub flags_ece: bool, // ECN-Echo
    pub flags_urg: bool, // Urgent
    pub flags_ack: bool, // Acknowledgment
    pub flags_psh: bool, // Push
    pub flags_rst: bool, // Reset
    pub flags_syn: bool, // Synchronize
    pub flags_fin: bool, // Finish
    /// Window size (16 bits)
    pub window: u16,
    /// Checksum (16 bits)
    pub checksum: u16,
    /// Urgent pointer (16 bits)
    pub urgent_pointer: u16,
    /// Options (variable)
    pub options: Vec<u32>,
}

pub struct Ipv4Header {
    // version: 4 bits
    pub version: u8,
    // Internet header length: 4 bits
    pub ihl: u8,
    // Terms of service: 8 bits
    pub tos: u8,
    // Total length: 16 bits
    pub total_length: u16,
    // Identification: 16 bits
    pub identification: u16,
    // Flags: 2 bits
    pub flags: u8,
    // Fragment offset, 14 bits
    pub frag_offset: u16,
    // Time to live: 8 bits
    pub ttl: u8,
    // Protocol: 8 bits
    pub proto: u8,
    // Header checksum: 16 bits
    pub checksum: u16,
    // Source address
    pub source_address: u32,
    // Destination address
    pub destination_address: u32, // Options
                                  // Empty for now
}
