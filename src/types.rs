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
