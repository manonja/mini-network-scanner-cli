use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::util::ipv4_checksum;
use std::env;
use std::net::Ipv4Addr;
mod types;
use types::TcpHeader;

const DEFAULT_PORT: u16 = 80;

#[allow(clippy::too_many_arguments)]
fn create_tcp_packet(
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
fn create_syn_packet(
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    options: Vec<u32>,
) -> TcpHeader {
    create_tcp_packet(
        source_port,
        destination_port,
        sequence_number,
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
        options,
    )
}

/// Verifies the TCP checksum of a received packet
/// Returns true if the checksum is valid, false otherwise
fn verify_tcp_packet(header: &TcpHeader, source_ip: &Ipv4Addr, dest_ip: &Ipv4Addr) -> bool {
    // Store the received checksum
    let received_checksum = header.checksum;

    // Create a copy and set its checksum to 0 for verification
    let mut header_copy = header.clone();
    header_copy.checksum = 0;

    // Compute the checksum of the received packet
    let computed_checksum = compute_tcp_checksum(&header_copy, source_ip, dest_ip);

    // The packet is valid if the computed checksum matches the received one
    received_checksum == computed_checksum
}

fn pack_tcp_header(header: &TcpHeader) -> Vec<u8> {
    let header_length_in_32_bit_words = 5 + header.options.capacity();
    let mut packed_header = Vec::with_capacity(header_length_in_32_bit_words * 4);

    println!("Header options length: {}", header.options.capacity());
    println!(
        "Header length in 32-bit words: {}",
        header_length_in_32_bit_words
    );
    println!("Packed header: {:#04x?}", packed_header);
    packed_header.extend_from_slice(&header.source_port.to_be_bytes());
    packed_header.extend_from_slice(&header.destination_port.to_be_bytes());
    packed_header.extend_from_slice(&header.sequence_number.to_be_bytes());
    packed_header.extend_from_slice(&header.ack_number.to_be_bytes());

    // let offset_and_reserved: u8 = (header_length << 4);
    let offset_and_reserved: u8 = (header_length_in_32_bit_words << 4) as u8;
    packed_header.push(offset_and_reserved);

    // Pack the flags into a single byte
    let flags: u8 = ((header.flags_cwr as u8) << 7)
        | ((header.flags_ece as u8) << 6)
        | ((header.flags_urg as u8) << 5)
        | ((header.flags_ack as u8) << 4)
        | ((header.flags_psh as u8) << 3)
        | ((header.flags_rst as u8) << 2)
        | ((header.flags_syn as u8) << 1)
        | (header.flags_fin as u8);
    packed_header.push(flags);

    packed_header.extend_from_slice(&header.window.to_be_bytes());
    // Next process the checksum
    packed_header.extend_from_slice(&header.checksum.to_be_bytes());
    // Next process the urgent pointer
    packed_header.extend_from_slice(&header.urgent_pointer.to_be_bytes());

    // Pack options using flat_map for efficient byte conversion
    packed_header.extend_from_slice(
        &header
            .options
            .iter()
            .flat_map(|o| o.to_be_bytes())
            .collect::<Vec<u8>>(),
    );

    packed_header
}

/// Computes the TCP checksum according to RFC 793.
/// The checksum is calculated over:
/// 1. TCP pseudo-header (containing IP information)
/// 2. TCP header (with checksum field set to 0)
/// 3. TCP data (if any)
fn compute_tcp_checksum(header: &TcpHeader, source_ip: &Ipv4Addr, dest_ip: &Ipv4Addr) -> u16 {
    // Create a copy of the header and set its checksum to 0
    // This is required because the checksum field must be 0 during calculation
    let mut header_copy = header.clone();
    header_copy.checksum = 0;
    let packed_header = pack_tcp_header(&header_copy);

    // skipword is the offset (in 16-bit words) to the checksum field in the TCP header
    // Since checksum is at byte offset 16, and we're counting 16-bit words, we divide by 2
    // So skipword = 16 / 2 = 8
    let skipword = 8; // Skip the 16-bit checksum field (at offset 16 bytes)

    // Create TCP pseudo-header required by RFC 793 for checksum calculation
    // The pseudo-header ensures that TCP segments are delivered to the correct destination
    // Format:
    // - source_ip (4 bytes)
    // - dest_ip (4 bytes)
    // - zeros (1 byte)
    // - protocol (1 byte, 6 for TCP)
    // - tcp_length (2 bytes)
    let tcp_length = packed_header.len() as u16;
    let mut pseudo_header = Vec::with_capacity(12);
    pseudo_header.extend_from_slice(&source_ip.octets()); // 4 bytes: Source IP
    pseudo_header.extend_from_slice(&dest_ip.octets()); // 4 bytes: Destination IP
    pseudo_header.push(0); // 1 byte: Reserved (must be zero)
    pseudo_header.push(6); // 1 byte: Protocol (6 for TCP)
    pseudo_header.extend_from_slice(&tcp_length.to_be_bytes()); // 2 bytes: TCP length (header + data)

    // Calculate the checksum using the pnet_packet function
    // Parameters:
    // - packed_header: The TCP header bytes
    // - skipword: Where to skip the checksum field
    // - pseudo_header: The TCP pseudo-header
    // - source_ip/dest_ip: IP addresses for additional verification
    // - IpNextHeaderProtocol(6): Indicates this is TCP
    ipv4_checksum(
        &packed_header,
        skipword,
        &pseudo_header,
        source_ip,
        dest_ip,
        IpNextHeaderProtocol(6), // TCP protocol number from IANA registry
    )
}

/// Creates a test vector with specified capacity
fn create_test_vector(size: usize) -> Vec<u32> {
    let mut v: Vec<u32> = Vec::new();
    v.reserve_exact(size);
    assert_eq!(size, v.capacity());
    v
}

// TODO: Implement a function that prints out the help message on the screen.
fn help(program_name: &str) {
    let help_message = format!("
************************************************************************************************

    Mini Network Scanner is a small CLI that can scan ports and retrieve basic system information 💜 

    HTTP Port Scan Requirements:
    - Checks TCP connection on port 80 (default HTTP port)
    - Connection timeout set to 1 second
    - Returns:
        ✓ 'Port open' - Successfully established TCP connection
        ✗ 'Port closed' - Failed to connect (port closed, filtered, or host unreachable)
    

    Usage: 
    {program_name} --help
    {program_name} -h

    {program_name} --scan <ip_address> [port]         # port is optional, defaults to 80
    {program_name} -s <ip_address> [port]

    Examples:
    {program_name} --scan 127.0.0.1           # Scans port 80 on localhost
    {program_name} --scan 192.168.1.1 443     # Scans port 443 on router

************************************************************************************************
", );
    println!("{}", help_message);
}

// macro_rules! print_mem_offset_bits {
//     ( $field:expr , $struct_name:ty , $field_name:expr) => {
//         {
//             let header_offset = std::mem::offset_of!($struct_name, $field_name) * 8;
//             let header_row = header_offset / 32;
//             let header_column = header_offset % 32;
//             println!("{}:\t\theader_offset {} \t\trow {},\t\toffset {}",
//                 $field, header_offset, header_row, header_column)
//         }
//     };
// }

fn main() {
    let args: Vec<String> = env::args().collect();

    // DEBUG CODE, remove later
    let source_ip = Ipv4Addr::new(192, 168, 0, 12);
    let dest_ip = Ipv4Addr::new(192, 168, 0, 10);

    // Create test options with size 6
    let options = create_test_vector(6);

    // Create the SYN packet first
    let mut syn_packet = create_syn_packet(60401, 80, 598238115, options);

    // Then compute its checksum with the IP addresses
    syn_packet.checksum = compute_tcp_checksum(&syn_packet, &source_ip, &dest_ip);

    let packed_syn_packet = pack_tcp_header(&syn_packet);
    println!("Source IP: {}", source_ip);
    println!("Destination IP: {}", dest_ip);
    println!("Packed SYN packet: {:#04x?}", packed_syn_packet);
    println!(
        "Checksum verification: {}",
        verify_tcp_packet(&syn_packet, &source_ip, &dest_ip)
    );

    if args.len() > 1 {
        match args[1].as_str() {
            "--help" | "-h" => {
                help(&args[0]);
                std::process::exit(0);
            }
            "--scan" | "-s" => {
                if args.len() < 3 {
                    println!("Please provide an IP address to scan");
                    std::process::exit(1);
                }
                let ip = &args[2];
                // Get port from arguments if provided, otherwise use default
                let port = if args.len() > 3 {
                    match args[3].parse::<u16>() {
                        Ok(p) => p,
                        Err(_) => {
                            println!("Invalid port number. Using default port {}", DEFAULT_PORT);
                            DEFAULT_PORT
                        }
                    }
                } else {
                    DEFAULT_PORT
                };
                println!("Scanning port {} on {}", port, ip);
            }
            _ => {
                println!("Invalid argument. Use --help to see usage.");
                std::process::exit(1);
            }
        }
    } else {
        println!("No arguments provided. Use --help to see usage.");
        std::process::exit(1);
    }
}
