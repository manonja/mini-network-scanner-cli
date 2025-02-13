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
#[allow(clippy::too_many_arguments)]
pub fn create_tcp_packet(
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    ack_number: u32,
    header_length: u8,
    reserved: u8,
    flags_cwr: bool,
    flags_ece: bool,
    flags_urg: bool,
    flags_ack: bool,
    flags_psh: bool,
    flags_rst: bool,
    flags_syn: bool,
    flags_fin: bool,
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
    options: Vec<u32>,
) -> TcpHeader {
    TcpHeader {
        source_port,
        destination_port,
        sequence_number,
        ack_number,
        header_length,
        reserved,
        flags_cwr,
        flags_ece,
        flags_urg,
        flags_ack,
        flags_psh,
        flags_rst,
        flags_syn,
        flags_fin,
        window,
        checksum,
        urgent_pointer,
        options,
    }
}
/// Creates a TCP SYN packet (used for initiating connections)
/// SYN packets are special TCP packets with the SYN flag set to true
pub fn create_syn_packet(source_port: u16, destination_port: u16) -> TcpHeader {
    create_tcp_packet(
        source_port,
        destination_port,
        0,     // sequence number
        0,     // ack number
        6,     // data offset, should be set by our packer
        0,     // reserved
        false, // CWR flag
        false, // ECE flag
        false, // URG flag
        false, // ACK flag
        false, // PSH flag
        false, // RST flag
        true,  // SYN flag - Set to true for SYN packet
        false, // FIN flag
        0,     // window size
        0,     // checksum (will be computed later)
        0,     // urgent pointer
        vec![0],
    )
}

impl TcpHeader {
    /// Calculate the header length in 32-bit words.
    /// This is the 5 fixed words plus one word per option.
    pub fn header_length_words(&self) -> u8 {
        5 + (self.options.len() as u8)
    }

    pub fn pack(self: &mut TcpHeader) -> Vec<u8> {
        let header_length = self.header_length_words();

        // Each word is 4 bytes, so the total length in bytes is:
        let total_length_bytes = header_length as usize * 4;
        let mut buffer = Vec::with_capacity(total_length_bytes);
        // let mut buffer = Vec::with_capacity(self.length_usize() * 4);

        println!("source port in buffer {}", self.source_port);
        println!("self {:?}", self);
        println!(
            "options lenght and capacity{:?}, {:?}",
            self.options.len(),
            self.options.capacity()
        );

        // Pack all fixed fields into buffer
        buffer.extend_from_slice(&self.source_port.to_be_bytes());
        buffer.extend_from_slice(&self.destination_port.to_be_bytes());
        buffer.extend_from_slice(&self.sequence_number.to_be_bytes());
        buffer.extend_from_slice(&self.ack_number.to_be_bytes());

        let offset_and_reserved: u8 = (header_length << 4) | (self.reserved & 0x0F);
        buffer.push(offset_and_reserved);

        let flags: u8 = ((self.flags_cwr as u8) << 7)
            | ((self.flags_ece as u8) << 6)
            | ((self.flags_urg as u8) << 5)
            | ((self.flags_ack as u8) << 4)
            | ((self.flags_psh as u8) << 3)
            | ((self.flags_rst as u8) << 2)
            | ((self.flags_syn as u8) << 1)
            | (self.flags_fin as u8);

        buffer.push(flags);

        buffer.extend_from_slice(&self.window.to_be_bytes());
        // Next process the checksum
        buffer.extend_from_slice(&self.checksum.to_be_bytes());
        // Next process the urgent pointer
        buffer.extend_from_slice(&self.urgent_pointer.to_be_bytes());

        // Pack options using flat_map for efficient byte conversion
        buffer.extend_from_slice(
            &self
                .options
                .iter()
                .flat_map(|o| o.to_be_bytes())
                .collect::<Vec<u8>>(),
        );

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tcp_header_pack() {
        // Expected TCP header (44 bytes) as seen in Wireshark:
        //   [0-1]   Source Port:       0xcf4a        (53066)
        //   [2-3]   Destination Port:  0x240d        (9229)
        //   [4-7]   Sequence Number:   0x0c08a8b4    (201894068)
        //   [8-11]  Ack Number:        0x00000000
        //   [12]    Data Offset:       11 (0xb0 when shifted left by 4 bits)
        //   [13]    Flags:             0x02         (only SYN set)
        //   [14-15] Window:            0xffff       (65535)
        //   [16-17] Checksum:          0xfe34
        //   [18-19] Urgent Pointer:    0x0000
        //   [20-43] Options (24 bytes, 6 words):
        //           0x02043fd8, 0x01030306, 0x0101080a, 0x036f186b, 0x00000000, 0x04020000
        let expected: Vec<u8> = vec![
            0xcf, 0x4a, // Source Port (53066)
            0x24, 0x0d, // Destination Port (9229)
            0x0c, 0x08, 0xa8, 0xb4, // Sequence Number (0x0c08a8b4)
            0x00, 0x00, 0x00, 0x00, // Ack Number (0)
            0xb0, // Data Offset: 11 << 4 = 0xb0
            0x02, // Flags: SYN only
            0xff, 0xff, // Window (65535)
            0xfe, 0x34, // Checksum (0xfe34)
            0x00, 0x00, // Urgent Pointer (0)
            // Options (24 bytes, 6 words)
            0x02, 0x04, 0x3f, 0xd8, // Option 1: 0x02043fd8
            0x01, 0x03, 0x03, 0x06, // Option 2: 0x01030306
            0x01, 0x01, 0x08, 0x0a, // Option 3: 0x0101080a
            0x03, 0x6f, 0x18, 0x6b, // Option 4: 0x036f186b
            0x00, 0x00, 0x00, 0x00, // Option 5: 0x00000000
            0x04, 0x02, 0x00, 0x00, // Option 6: 0x04020000
        ];

        // Build the options vector. Note the update on the 4th option.
        let options = vec![
            0x02043fd8, 0x01030306, 0x0101080a, 0x036f186b, // Updated to match Wireshark
            0x00000000, 0x04020000,
        ];

        // Create the TCP header with the given values.
        // The header length is computed as 5 (base header words) + options.len() (6) = 11 words.
        let mut tcp_header = create_tcp_packet(
            53066,      // source_port updated to 53066
            9229,       // destination_port updated to 9229
            0x0c08a8b4, // sequence_number updated to 0x0c08a8b4
            0,          // ack_number
            0,          // header_length parameter (ignored in pack())
            0,          // reserved
            false,      // flags: CWR
            false,      // flags: ECE
            false,      // flags: URG
            false,      // flags: ACK
            false,      // flags: PSH
            false,      // flags: RST
            true,       // flags: SYN (only SYN is set)
            false,      // flags: FIN
            65535,      // window size
            0xfe34,     // checksum (precomputed)
            0,          // urgent pointer
            options,    // options vector (6 words)
        );

        // Pack the header.
        let packed = tcp_header.pack();

        // For debugging, print the hex dump of the packed header.
        println!(
            "TCP Header packed: 0x{:02x?}\nExpected: 0x{:02x?}",
            packed, expected
        );

        assert_eq!(
            packed, expected,
            "Packed TCP header did not match expected output"
        );
    }

    #[test]
    fn test_tcp() {
        test_tcp_header_pack();
    }
}
