use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::util::ipv4_checksum;
use std::os::fd::AsRawFd;
use socket2::Protocol;
use std::net::SocketAddr;
use socket2::SockAddr;
use rand::prelude::*;
use socket2::{Domain, Socket, Type};
use std::env;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::time::Duration;
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
    // sequence_number: u32,
    options: Vec<u32>,
) -> TcpHeader {
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
        options,
    )
}

/// Verifies the TCP checksum of a received packet
/// Returns true if the checksum is valid, false otherwise
// fn verify_tcp_packet(header: &TcpHeader, source_ip: &Ipv4Addr, dest_ip: &Ipv4Addr) -> bool {
//     // Store the received checksum
//     let received_checksum = header.checksum;

//     // Create a copy and set its checksum to 0 for verification
//     let mut header_copy = header.clone();
//     header_copy.checksum = 0;

//     // Compute the checksum of the received packet
//     let computed_checksum = compute_tcp_checksum(&header_copy, source_ip, dest_ip);

//     // The packet is valid if the computed checksum matches the received one
//     received_checksum == computed_checksum
// }

fn pack_tcp_header(header: &TcpHeader) -> Vec<u8> {
    let header_length_in_32_bit_words = 5 + header.options.capacity();
    let mut packed_header = Vec::with_capacity(header_length_in_32_bit_words * 4);

    // println!("Header options length: {}", header.options.capacity());
    // println!(
    //     "Header length in 32-bit words: {}",
    //     header_length_in_32_bit_words
    // );
    // println!("Packed header: {:#04x?}", packed_header);
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

/// Computes the IPv4 header checksum
fn compute_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Process 2 bytes at a time
    for i in (0..header.len()).step_by(2) {
        sum += ((header[i] as u32) << 8 | header[i + 1] as u32) as u32;
    }
    // Add carried bits
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
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

// Construct the complete IP packet
fn construct_ip_packet(
    tcp_header: &TcpHeader,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
) -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Calculate total length (IP header + TCP header + options)
    let tcp_header_len = 20 + tcp_header.options.len() * 4;  // TCP header + options
    let total_length: u16 = (20 + tcp_header_len) as u16;  // IP header + TCP size
    
    // IP Header (20 bytes)
    packet.extend_from_slice(&[
        0x45, 0x00,                         // Version, IHL, DSCP, ECN
    ]);
    packet.extend_from_slice(&total_length.to_be_bytes()); // Total Length in network byte order
    packet.extend_from_slice(&[
        0x00, 0x00,                         // Identification
        0x40, 0x00,                         // Flags (Don't Fragment), Fragment Offset
        0x40, 0x06,                         // TTL (64), Protocol (6 for TCP)
        0x00, 0x00,                         // Header Checksum
    ]);

    // Add source and destination IPs
    packet.extend_from_slice(&source_ip.octets());
    packet.extend_from_slice(&dest_ip.octets());

    // Add TCP header
    let packed_tcp = pack_tcp_header(tcp_header);
    packet.extend_from_slice(&packed_tcp);

    // Calculate IP header checksum
    let ip_checksum = compute_ip_checksum(&packet[..20]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = ip_checksum as u8;

    packet
}

// Define our port states
#[derive(Debug)]
enum PortState {
    Open,
    Closed,
    Filtered,
}

fn scan_single_port(
    socket: &Socket,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
    dest_port: u16,
) -> std::io::Result<PortState> {
    println!("\n📦 Creating SYN packet...");
    
    let source_port = rand::thread_rng().gen_range(32768..65535);
    println!("  Selected source port: {}", source_port);
    
    let options = create_test_vector(6);
    let mut syn_packet = create_syn_packet(source_port, dest_port, options);
    println!("  SYN packet created");
    println!("    → Source Port: {}", syn_packet.source_port);
    println!("    → Destination Port: {}", syn_packet.destination_port);
    println!("    → Sequence Number: {}", syn_packet.sequence_number);
    println!("    → SYN Flag: {}", syn_packet.flags_syn);

    println!("\n🔧 Computing TCP checksum...");
    syn_packet.checksum = compute_tcp_checksum(&syn_packet, source_ip, dest_ip);
    println!("  Checksum computed: 0x{:04x}", syn_packet.checksum);

    println!("\n📄 Constructing IP packet...");
    let complete_packet = construct_ip_packet(&syn_packet, source_ip, dest_ip);
    println!("  Total size: {} bytes", complete_packet.len());
    println!("  First 20 bytes (IP header): {:02x?}", &complete_packet[..20]);
    println!("  Next 20 bytes (TCP header): {:02x?}", &complete_packet[20..40]);

    println!("\n🔌 Configuring socket...");
    
    // Create proper sockaddr_in structure for binding
    // We use port 0 to let the kernel choose a random port.
    let bind_addr = SockAddr::from(SocketAddr::new((*source_ip).into(), 0));
    println!("  Created bind address");
    
    socket.bind(&bind_addr).unwrap();
    let local_addr = socket.local_addr().unwrap();
    println!("  Socket bound successfully {:?}", local_addr.as_socket_ipv4().unwrap().port());

    // Set IP_HDRINCL after binding
    unsafe {
        let hdrincl: libc::c_int = 1;
        let result = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &hdrincl as *const _ as *const libc::c_void,
            std::mem::size_of_val(&hdrincl) as libc::socklen_t,
        );
        if result == -1 {
            println!("  ⚠️  Failed to set IP_HDRINCL");
        } else {
            println!("  IP_HDRINCL set manually");
        }
    }

    // Create destination sockaddr
    let dest_addr = SockAddr::from(SocketAddr::new((*dest_ip).into(), dest_port));
    println!("  Created destination socket:");

    // Send the packet without connect()
    println!("\n📤 Sending SYN packet...");
    match socket.send_to(&complete_packet, &dest_addr) {
        Ok(bytes) => println!("  ✅ Sent {} bytes successfully", bytes),
        Err(e) => {
            println!("  ❌ Send failed: {} (code: {})", 
                e, e.raw_os_error().unwrap_or(-1));
            return Err(e);
        }
    }

    println!("\n📥 Waiting for response (timeout: 1.5s)...");
    let mut buf = [MaybeUninit::uninit(); 65535];
    socket.set_read_timeout(Some(Duration::from_millis(1500)))?;

    // Wait for response
    match socket.recv(&mut buf) {
        Ok(n) if n >= 40 => {
            println!("  Received {} bytes", n);
            
            let received_data = &buf[..n];
            let buf: Vec<u8> = received_data
                .iter()
                .map(|b| unsafe { b.assume_init() })
                .collect();

            let ip_header_len = (buf[0] & 0x0f) * 4;
            let tcp_flags = buf[(ip_header_len + 13) as usize];
            println!("  TCP Flags received: 0x{:02x}", tcp_flags);

            Ok(match tcp_flags {
                f if f & 0x12 == 0x12 => {
                    println!("  🟢 Detected: SYN-ACK (Port Open)");
                    PortState::Open
                },
                f if f & 0x04 == 0x04 => {
                    println!("  🔴 Detected: RST (Port Closed)");
                    PortState::Closed
                },
                _ => {
                    println!("  🟡 Detected: Unknown response (Port Filtered)");
                    PortState::Filtered
                }
            })
        }
        Ok(n) => {
            println!("  Received packet too small: {} bytes", n);
            Ok(PortState::Filtered)
        },
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            println!("  No response received (timeout)");
            Ok(PortState::Filtered)
        }
        Err(e) => {
            println!("  ❌ Error receiving response: {}", e);
            Err(e)
        }
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "--help" | "-h" => {
                help(&args[0]);
                return Ok(());
            }
            "--scan" | "-s" => {
                if args.len() < 3 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Missing IP address",
                    ));
                }

                // Parse the IP address (arg[2])
                let dest_ip = args[2].parse::<Ipv4Addr>().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid IP address"
                    )
                })?;

                // Get port from arguments if provided, otherwise use default
                let destination_port = if args.len() > 3 {
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

                println!("🚀 Starting TCP SYN Scanner");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("Target: {}:{}", dest_ip, destination_port);

                println!("\n📡 Creating raw socket...");
                let socket = Socket::new_raw(Domain::IPV4, Type::RAW, Some(Protocol::from(0)))?;  // Use Protocol::RAW
                println!("  Raw socket created");       

                socket.set_header_included_v4(true)?;         

                // Don't set header_included here, we'll do it after binding
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                println!("  Read timeout set");
                socket.set_write_timeout(Some(Duration::from_secs(5)))?;
                println!("  Write timeout set");

                // Use localhost as source IP for now
                let source_ip = Ipv4Addr::new(127, 0, 0, 1);

                println!("\n📝 Scan Configuration:");
                println!("  Source IP: {}", source_ip);
                println!("  Destination IP: {}", dest_ip);
                println!("  Destination Port: {}", destination_port);
                println!("  Timeout: 1500ms");

                // Call scan_single_port
                match scan_single_port(&socket, &source_ip, &dest_ip, destination_port)? {
                    PortState::Open => println!("\n✅ Port {} is OPEN!", destination_port),
                    PortState::Closed => println!("\n❌ Port {} is CLOSED.", destination_port),
                    PortState::Filtered => println!("\n🔒 Port {} is FILTERED.", destination_port),
                }

                Ok(())
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid argument. Use --help to see usage.",
                ));
            }
        }
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No arguments provided. Use --help to see usage.",
        ));
    }
}