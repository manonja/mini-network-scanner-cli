use crate::hextools::format_hexdump;

use super::{checksum::rfc1071_checksum, tcp::TcpHeader};
use std::net::Ipv4Addr;

const TCP_PROTOCOL_NUM: u8 = 6;
const IP_HEADER_LENGTH: u16 = 20;

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

pub fn create_ip_packet(
    total_length: u16,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
    protocol: u8,
) -> Vec<u8> {
    let mut new_ip_packet = Ipv4Header {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length,
        identification: 0,
        flags: 0b010, // Set only 3 bits flag
        frag_offset: 0,
        ttl: 255,
        proto: protocol,
        checksum: 0, // Let checksum be computed
        source_address: source_ip.to_bits(),
        destination_address: dest_ip.to_bits(),
    };

    println!("source address: {}", source_ip);
    println!("destination address: {}", dest_ip);

    new_ip_packet.pack()
}

impl Ipv4Header {
    pub fn pack(self: &mut Ipv4Header) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(usize::from(IP_HEADER_LENGTH));

        // 1. First byte: Version (4 bits) + IHL (4 bits)
        let v_ihl = (self.version << 4) | (self.ihl & 0x0F);
        buffer.push(v_ihl);
        buffer.extend_from_slice(&self.tos.to_be_bytes());
        buffer.extend_from_slice(&self.total_length.to_be_bytes());
        buffer.extend_from_slice(&self.identification.to_be_bytes());

        // 2. Correctly encode Flags (3 bits) + Fragment Offset (13 bits)
        let flags_fog_bytes = ((self.flags as u16) << 13) | (self.frag_offset & 0x1FFF);
        buffer.extend_from_slice(&flags_fog_bytes.to_be_bytes());
        // We need to add the remaining byte that represents the 2 bits for
        // flags and 14 for fragment offset.
        buffer.push(self.ttl);
        buffer.push(self.proto);
        buffer.extend_from_slice(&self.checksum.to_be_bytes());
        buffer.extend_from_slice(&self.source_address.to_be_bytes());
        buffer.extend_from_slice(&self.destination_address.to_be_bytes());

        // 3. Compute checksum (if it's not already set)
        if self.checksum == 0 {
            // We could also pop 10 u8 from buffer and set checksum and the rest for
            // a small performance gain.
            self.checksum = u16::from_be_bytes(rfc1071_checksum(&buffer));
            buffer[10..12].copy_from_slice(&self.checksum.to_be_bytes());
            return self.pack();
        }

        buffer
    }
}

// Construct the complete TCP/IP packet
pub fn construct_ip_package_for_tcp_header(
    tcp_header: &mut TcpHeader,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
) -> Vec<u8> {
    // --- Step 1: Pack the TCP header and zero out the checksum field ---
    let mut tcp_header_bytes = tcp_header.pack();
    // The checksum field is at offset 16-17 in the TCP header.
    if tcp_header_bytes.len() >= 18 {
        tcp_header_bytes[16] = 0;
        tcp_header_bytes[17] = 0;
    } else {
        eprintln!("Error: TCP header is too short to zero out checksum.");
    }

    // Compute the TCP segment length (header + options + payload, if any)
    let tcp_length = tcp_header_bytes.len() as u16;

    // --- Step 2: Build the pseudo header ---
    // Pseudo header structure:
    // [Source IP (4 bytes)] + [Destination IP (4 bytes)] +
    // [Zero (1 byte)] + [Protocol (1 byte)] + [TCP length (2 bytes)]
    let mut pseudo_header = Vec::with_capacity(12);
    pseudo_header.extend_from_slice(&source_ip.octets());
    pseudo_header.extend_from_slice(&dest_ip.octets());
    pseudo_header.push(0); // zero byte
    pseudo_header.push(TCP_PROTOCOL_NUM); // TCP protocol number (typically 6)
    pseudo_header.extend_from_slice(&tcp_length.to_be_bytes());

    // --- Step 3: Combine pseudo header and TCP header bytes ---
    let mut checksum_buffer = Vec::new();
    checksum_buffer.extend_from_slice(&pseudo_header);
    checksum_buffer.extend_from_slice(&tcp_header_bytes);

    // If the combined length is odd, pad with an extra zero byte.
    if checksum_buffer.len() % 2 != 0 {
        checksum_buffer.push(0);
    }

    // --- Step 4: Compute the checksum over the entire buffer ---
    let checksum_bytes = rfc1071_checksum(&checksum_buffer);
    let checksum = u16::from_be_bytes(checksum_bytes);
    tcp_header.checksum = checksum;
    println!("Computed TCP checksum: 0x{:04x}", checksum);

    // --- Step 5: Repack the TCP header with the correct checksum ---
    let final_tcp_packet = tcp_header.pack();

    println!("Raw TCP package:");
    println!("{}", format_hexdump(&final_tcp_packet));

    // --- Step 6: Create the IP packet ---
    // Calculate total length (IP header + TCP header + options)
    let ip_packet_length = (usize::from(IP_HEADER_LENGTH) + final_tcp_packet.len()) as u16;
    println!("TCP packet length: {}", final_tcp_packet.len());
    println!("Total length tcp+ip: {}", ip_packet_length);

    // Create the IP header using the computed total length.
    let mut ip_packet = create_ip_packet(ip_packet_length, source_ip, dest_ip, TCP_PROTOCOL_NUM);

    // Append the finalized TCP header to the IP header.
    ip_packet.extend_from_slice(&final_tcp_packet);

    ip_packet
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_checksum_with_wikipedia_example() {
        // The Wikipedia example IP header (without the checksum field)
        let ip_header: [u8; 18] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xc0, 0xa8, 0x00, 0x01,
            0xc0, 0xa8, 0x00, 0xc7,
        ];

        let computed_checksum = rfc1071_checksum(&ip_header);
        let expected_checksum: [u8; 2] = [0xb8, 0x61]; // "b861" in hex

        assert_eq!(
            computed_checksum, expected_checksum,
            "Checksum did not match expected value!"
        );
        println!(
            "Wikipedia example checksum results: {:04x?}, {:04x?}",
            computed_checksum, expected_checksum
        );
    }
    #[test]
    fn ip_header_test() {
        test_checksum_with_wikipedia_example();
    }
}
