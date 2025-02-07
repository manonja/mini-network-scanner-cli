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
        0,     // data offset, should be set by our packer
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
    pub fn pack(self: &mut TcpHeader) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.length_usize() * 4);

        println!("source port in buffer {}", self.source_port);
        println!("self {:?}", self);
        println!(
            "options lenght and capacity{:?}, {:?}",
            self.options.len(),
            self.options.capacity()
        );

        // Pack all fields into buffer
        buffer.extend_from_slice(&self.source_port.to_be_bytes());
        buffer.extend_from_slice(&self.destination_port.to_be_bytes());
        buffer.extend_from_slice(&self.sequence_number.to_be_bytes());
        buffer.extend_from_slice(&self.ack_number.to_be_bytes());

        // let offset_and_reserved: u8 = (self_length << 4);
        let offset_and_reserved: u8 = self.header_length << 4;
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

    /// The TCP length is 20 bytes, plus 4 bytes for each option.
    pub fn length(self: &TcpHeader) -> u32 {
        5 + u32::try_from(self.options.capacity()).unwrap()
    }

    /// The TCP length is 20 bytes, plus 4 bytes for each option in usize so not really accurate if converted to bytes.
    pub fn length_usize(self: &TcpHeader) -> usize {
        5 + self.options.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tcp_header_pack() {
        // Expected TCP header (44 bytes):
        // Breakdown:
        //   [0-1]   Source Port:       0xeb1e        (60190)
        //   [2-3]   Destination Port:  0x1f90        (8080)
        //   [4-7]   Sequence Number:   0xe608ebd5
        //   [8-11]  Ack Number:        0x00000000
        //   [12]    Data Offset:       11 (0xb0 when shifted left by 4 bits)
        //   [13]    Flags:             0x02         (only SYN set)
        //   [14-15] Window:            0xffff       (65535)
        //   [16-17] Checksum:          0xfe34
        //   [18-19] Urgent Pointer:    0x0000
        //   [20-43] Options (6 x 4 bytes):
        //           0x02043fd8, 0x01030306, 0x0101080a, 0x3648aacd, 0x00000000, 0x04020000
        let expected: Vec<u8> = vec![
            0xeb, 0x1e, // Source Port (60190)
            0x1f, 0x90, // Destination Port (8080)
            0xe6, 0x08, 0xeb, 0xd5, // Sequence Number (0xe608ebd5)
            0x00, 0x00, 0x00, 0x00, // Ack Number (0)
            0xb0, // Data Offset: (11 << 4) = 0xb0 (44-byte header)
            0x02, // Flags: 0x02 (SYN only)
            0xff, 0xff, // Window (65535)
            0xfe, 0x34, // Checksum (0xfe34)
            0x00, 0x00, // Urgent Pointer (0)
            // Options (24 bytes, 6 words)
            0x02, 0x04, 0x3f, 0xd8, // Option 1: MSS option: 0x02043fd8
            0x01, 0x03, 0x03, 0x06, // Option 2: (0x01030306)
            0x01, 0x01, 0x08, 0x0a, // Option 3: (0x0101080a)
            0x36, 0x48, 0xaa, 0xcd, // Option 4: (0x3648aacd)
            0x00, 0x00, 0x00, 0x00, // Option 5: (0x00000000)
            0x04, 0x02, 0x00, 0x00, // Option 6: (0x04020000)
        ];

        // Build the options vector.
        // Make sure each u32 is given in hexadecimal exactly as expected.
        let options = vec![
            0x02043fd8, 0x01030306, 0x0101080a, 0x3648aacd, 0x00000000, 0x04020000,
        ];

        // Create the TCP header with the given values.
        // Note: The data offset in the final header is computed as:
        //       5 (base header words) + options.len() (6) = 11 words.
        let mut tcp_header = create_tcp_packet(
            60190,      // source_port
            8080,       // destination_port
            0xe608ebd5, // sequence_number (nonzero to match expected)
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
            0xfe34,     // checksum (assumed precomputed)
            0,          // urgent pointer
            options,    // options: 6 words (24 bytes)
        );

        // Pack the header.
        let packed = tcp_header.pack();

        // For debugging you might print out the hex dump:
        // dump_hex_file(&packed);

        // Assert that the packed header matches the expected byte sequence.

        println!(
            "TCP Header packed and expected 0x{:02x?},0x{:02x?}",
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
