/// Represents the structure of a TCP header
#[derive(Debug)]
// FIX: change to set alignment big endian (required for TCP) and also ensure that the struct is packed
#[repr(C)]
pub struct TcpHeader {
    /// Source port (16 bits)
    pub source_port: u16,
    /// Destination port (16 bits)
    pub destination_port: u16,
    /// Sequence number (32 bits) - For new connections, this is a random value
    pub sequence_number: u32,
    /// Acknowledgment number (32 bits) - Next expected sequence number
    pub acknowledgment_number: u32,
    /// (DO) Data offset/Header length (4 bits)
    pub header_offset: u8,
    /// Reserved bits (3 bits) - Always set to 0
    pub reserved: u8,
    /// Control flags (9 bits)
    pub flags_urg: bool,
    pub flags_ack: bool,
    pub flags_psh: bool,
    pub flags_rst: bool,
    pub flags_syn: bool,
    pub flags_fin: bool,
    /// Window size (16 bits) - Number of bytes receiver is willing to receive
    pub window: u16,
    /// Checksum (16 bits) - For error checking
    pub checksum: u16,
    /// Urgent pointer (16 bits) - Used when URG flag is set
    pub urgent_pointer: u16,
    /// Optional field (0-320 bits) // FIX: set to fixed bit size
    pub options: Vec<u32>,
}
