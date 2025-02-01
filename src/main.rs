use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::util::ipv4_checksum;
use socket2::Protocol;
use socket2::{Domain, Socket, Type};
use std::env;

use std::net::SocketAddr;
mod types;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use types::TcpHeader;

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
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
#[allow(dead_code)]
fn create_syn_packet(source_port: u16, destination_port: u16) -> TcpHeader {
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

#[allow(dead_code)]
fn pack_tcp_header(header: &TcpHeader) -> Vec<u8> {
    // The TCP header length is 20 bytes, plus 4 bytes for each option
    let header_length_in_32_bit_words = 5 + header.options.capacity();
    let mut packed_header = Vec::with_capacity(header_length_in_32_bit_words * 4);

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
#[allow(dead_code)]
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
#[allow(dead_code)]
fn create_test_vector(size: usize) -> Vec<u32> {
    let mut v: Vec<u32> = Vec::new();
    v.reserve_exact(size);
    assert_eq!(size, v.capacity());
    v
}

/// Computes the IPv4 header checksum
#[allow(dead_code)]
fn compute_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Process 2 bytes at a time
    for i in (0..header.len()).step_by(2) {
        sum += (header[i] as u32) << 8 | header[i + 1] as u32;
    }
    // Add carried bits
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Creates an IPv4 packet with the given parameters
#[allow(dead_code)]
fn create_ip_packet(
    total_length: u16,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
    protocol: u8,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20); // IPv4 header is 20 bytes

    // Version (4) and IHL (5 words = 20 bytes) combined: 0x45
    packet.push(0x45);
    // DSCP (0) and ECN (0)
    packet.push(0x00);
    // Total Length (16 bits)
    packet.extend_from_slice(&total_length.to_be_bytes());
    // Identification (16 bits)
    packet.extend_from_slice(&[0x00, 0x00]);
    // Flags (Don't Fragment) and Fragment Offset
    packet.extend_from_slice(&[0x40, 0x00]);
    // TTL (64) and Protocol
    packet.extend_from_slice(&[64, protocol]);
    // Header Checksum (will be filled later)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Source and Destination IPs using flat_map
    packet.extend([source_ip, dest_ip].iter().flat_map(|ip| ip.octets()));

    // Compute and set IP header checksum
    let checksum = compute_ip_checksum(&packet);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = checksum as u8;

    packet
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

    {program_name} --scan <ip_address>:<port>  --src <source_ip>
    {program_name} -s <ip_address>:<port> -r <source_ip>

    Examples:
    {program_name} --scan 127.0.0.1:80 --src 127.0.0.1        # Scans port 80 on localhost
    {program_name} --scan 192.168.1.1:443 -r 127.0.0.1


************************************************************************************************
", );
    println!("{}", help_message);
}

// Construct the complete TCP/IP packet
#[allow(dead_code)]
fn construct_ip_package_for_tcp_header(
    tcp_header: &TcpHeader,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
) -> Vec<u8> {
    // First create the TCP header with checksum
    let tcp_packet = pack_tcp_header(tcp_header);

    // Calculate total length (IP header + TCP header + options)
    let total_length = (20 + tcp_packet.len()) as u16;
    println!("TCP packet length: {}", tcp_packet.len());
    println!("Total length tcp+ip: {}", total_length);

    // Create IP packet
    let mut packet = create_ip_packet(
        total_length,
        source_ip,
        dest_ip,
        6, // TCP protocol number
    );

    // Add TCP header and data
    packet.extend_from_slice(&tcp_packet);

    packet
}

// Define our port states
#[allow(dead_code)]
#[derive(Debug)]
enum PortState {
    Open,
    Closed,
    Filtered,
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No arguments provided. Use --help to see usage.",
        ));
    } else if args.len() == 2 {
        match args[1].as_str() {
            "--help" | "-h" => {
                help(&args[0]);
                return Ok(());
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid argument. Use --help to see usage.",
                ));
            }
        }
    } else if args.len() % 2 != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid number of arguments. Use --help to see usage.",
        ));
    }

    let args_without_program_name = &args[1..];

    let arg_tuples = args_without_program_name.chunks(2).collect::<Vec<_>>();

    let mut dest_ip: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    let mut destination_port: u16 = 0;
    let mut source_ip: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

    println!("Arg tuples: {:?}", arg_tuples);

    for iter in arg_tuples {
        match [iter[0].as_str(), iter[1].as_str()] {
            ["--scan" | "-s", dest_ip_and_port] => {
                dest_ip = dest_ip_and_port.split(":").collect::<Vec<&str>>()[0]
                    .parse::<Ipv4Addr>()
                    .unwrap();
                destination_port = dest_ip_and_port.split(":").collect::<Vec<&str>>()[1]
                    .parse::<u16>()
                    .unwrap();
            }
            ["--src" | "-r", source_ip_string] => {
                source_ip = source_ip_string.parse::<Ipv4Addr>().unwrap();
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid argument. Use --help to see usage.",
                ));
            }
        }
    }

    println!("Requested IP: {}", dest_ip);
    println!("Requested Port: {}", destination_port);
    println!("Requested Source IP: {}", source_ip);

    tcp_syn_scan(&source_ip, &dest_ip, destination_port)?;
    println!("Scan complete");

    Ok(())
}

fn tcp_syn_scan(
    source_ip: &Ipv4Addr,
    destination_ip: &Ipv4Addr,
    destination_port: u16,
) -> std::io::Result<PortState> {
    println!("🚀 Starting TCP SYN Scanner");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Target: {}:{}", destination_ip, destination_port);

    // 1. Create a raw socket
    println!("\n📡 Creating raw socket...");
    let raw_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;

    let lowest_listen_port = 1024;
    let source_port = rand::thread_rng().gen_range(lowest_listen_port..u16::MAX);
    let raw_socket_address = SocketAddr::new(IpAddr::V4(*source_ip), source_port);
    let socket_at_destination = SocketAddr::new(IpAddr::V4(*destination_ip), destination_port);
    println!("We will try to bind to port {:?}", source_port);
    println!("Socket address and port: {:?}", raw_socket_address);

    // let raw_socket_address = raw_socket_address.into();
    let socket_at_destination = socket_at_destination.into();

    // raw_socket.bind(&raw_socket_address)?;
    raw_socket.connect(&socket_at_destination)?;
    println!(
        "We should be connected to {}:{}, let's check... ",
        destination_ip, destination_port
    );

    match raw_socket.peer_addr() {
        Ok(_) => println!("🚀"),
        Err(error) => println!("😵 {}", error),
    }

    // Next, let's create the TCP SYN package
    let mut syn_packet = create_syn_packet(source_port, destination_port);
    syn_packet.checksum = compute_tcp_checksum(&syn_packet, source_ip, destination_ip);
    // Let's add the IP header
    let ip_syn_package =
        construct_ip_package_for_tcp_header(&syn_packet, source_ip, destination_ip);
    println!("Let's send our package");
    println!("Length of our ip_package {}", ip_syn_package.len());
    let mut buffer: [u8; 44] = [0; 44];
    // Ugly copy of our vec into ip package
    for (vec_ip_package_iter, buf_iter) in ip_syn_package.iter().zip(buffer.iter_mut()) {
        *buf_iter = *vec_ip_package_iter;
    }

    // Let's dump the buffer to hex.
    for word in ip_syn_package.chunks(2).collect::<Vec<_>>() {
        println!("{:02x}{:02x}", word[0], word[1]);
    }

    let send_result = raw_socket.send(&buffer);

    match send_result {
        Ok(_) => println!("Successfully sent"),
        Err(error) => println!("OOps 💩: {}", error),
    }

    // Structure for Mac OS X is explained in the [kernel](https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/netinet/in.h#L397)
    // Let's set-up an address for bind.

    // let mut addr = sockaddr_in {
    //     sin_len: std::mem::size_of::<sockaddr_in>() as u8,
    //     sin_family: AF_INET as u8,
    //     sin_port: random_port.to_be(),  // Port in network byte order
    //     sin_addr: in_addr {
    //         s_addr: source_ip.to_bits().to_be()
    //     },
    //     sin_zero: [0; 8]
    // };

    // let mut bind_result = unsafe {
    //     let addr_ptr = &addr as *const _ as *const sockaddr;
    //     libc::bind(raw_socket.as_raw_fd(), addr_ptr, std::mem::size_of_val(&addr) as libc::socklen_t)
    // };

    // if bind_result == -1 {
    //     return Err(std::io::Error::last_os_error());
    // }

    // println!("We successfully bound");

    // // 2. Set IP_HDRINCL
    // let one: i32 = 1;
    // unsafe {
    //     libc::setsockopt(
    //         raw_socket.as_raw_fd(),
    //         libc::IPPROTO_IP,
    //         libc::IP_HDRINCL,
    //         &one as *const i32 as *const libc::c_void,
    //         std::mem::size_of_val(&one) as libc::socklen_t,
    //     )
    // };

    // println!("We successfully set IP_HDRINCL");

    // TODO: Set-up TCP header
    // TODO: Set-up IP header
    // TODO: Send IP packet
    // TODO: Wait for response
    // TODO: Return port state

    // Set-up IP header
    // let mut ip = Ipv4 {
    //     version: 4,
    //     header_length: 5,
    //     dscp: 0,
    //     ecn: 0,
    //     // total_length: 20 + tcp_packet.len() as u16,
    //     total_length: 20 as u16,
    //     identification: 0,
    //     flags: 0,
    //     fragment_offset: 0,
    //     ttl: 64,
    //     next_level_protocol: IpNextHeaderProtocol(6),
    //     checksum: 0,  // TODO: verify correctness
    //     source: *source_ip,
    //     destination: *dest_ip,
    //     options: vec![],  // TODO: verify correctness
    //     payload: vec![], // TODO: verify correctness (you probably need to add the TCP packet)
    // };

    // // We need to define our destination address
    // let mut dest_addr = sockaddr_in {
    //     sin_len: (std::mem::size_of_val(&addr) as libc::socklen_t).try_into().unwrap(),
    //     sin_family: AF_INET as u8,
    //     sin_port: destination_port.to_be(),
    //     sin_addr: in_addr {
    //         s_addr: dest_ip.to_bits().to_be()
    //     },
    //     sin_zero: [0; 8]
    // };

    // let send_result = unsafe {
    //     let dest_addr_ptr = &dest_addr as *const _ as *const sockaddr;
    //     // Let us convert ipv4 to const void*
    //     let buffer = &ip as *const _ as *const libc::c_void;
    //     libc::sendto(
    //         raw_socket.as_raw_fd(),
    //         buffer,
    //         (std::mem::size_of_val(&ip) as libc::socklen_t).try_into().unwrap(),
    //         0,
    //         dest_addr_ptr,
    //         std::mem::size_of_val(&dest_addr) as libc::socklen_t);
    // };

    // if send_result == -1 {
    //     return Err(std::io::Error::last_os_error());
    // }

    // println!("We successfully sent the IP packet");

    // loop {
    //     // Let us receive the response
    //     let mut recv_buffer = [0u8; 65535];
    //     let recv_result = unsafe {
    //         let dest_addr_ptr = &dest_addr as *const _ as *const sockaddr;
    //         libc::recvfrom(
    //             raw_socket.as_raw_fd(),
    //             recv_buffer.as_mut_ptr() as *mut libc::c_void,
    //             (recv_buffer.len() as libc::socklen_t).try_into().unwrap(),
    //             0,
    //             dest_addr_ptr,
    //             std::mem::size_of_val(&dest_addr) as libc::socklen_t
    //         );
    //     };

    //     if recv_result == -1 {
    //         return Err(std::io::Error::last_os_error());
    //     }

    //     // Next we need to convert our recv_buffer to an ip packet
    //     let ip_packet = unsafe {
    //         std::slice::from_raw_parts(recv_buffer.as_ptr() as *const Ipv4, (recv_buffer.len() as libc::socklen_t).try_into().unwrap())
    //     };

    //     // Let's grab our tcp header
    //     let raw_tcp_package = ip_packet[0].payload;

    // TODO:
    // 1. convert the raw_tcp_package to a tcp package and back out the header
    // 2. check if the tcp header has the SYN flag set
    // 3. if it does, return PortState::Open
    // 4. if it doesn't, return PortState::Closed

    // Clean up memory

    Ok(PortState::Open)
}

// println!("We are going to try random port: {}", src_port);
// // 3. Bind to the assigned port
// let raw_addr = SocketAddr::new(IpAddr::V4(*source_ip), src_port);
// socket.bind(&raw_addr.into())?;
// println!(
//     "Raw socket bound successfully {}",
//     socket
//         .local_addr()
//         .unwrap()
//         .as_socket_ipv4()
//         .unwrap()
//         .port()
// );
// println!("address: {:?}", raw_addr);

// 0. Set socket options to use libc::IPPROTO_IP and libc::IP_HDRINCL

// 1. Create destination address
// 2. Create tcp syn package
// 3. Create IP package
// 4. Send IP package to receiving address over raw_socket
// 5. Start loop
// 6. In loop wait for response using poll(2)
// 7. If response is received, return port state
// 8. If no response is received, return port state

// let mut addr_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
// let mut len = mem::size_of_val(&addr_storage) as libc::socklen_t;
//  // The `getsockname(2)` system call will intiliase `storage` for
//  // us, setting `len` to the correct length.
// let res = unsafe {
//     libc::getsockname(
//         socket.as_raw_fd(),
//         (&mut addr_storage as *mut libc::sockaddr_storage).cast(),
//         &mut len,
//     )
// };

// if res == -1 {
//     return Err(io::Error::last_os_error());
// }

// let address = unsafe { SockAddr::new(addr_storage, len) };

// create_and_send_syn_packet(&raw_socket, src_port, dest_ip, destination_port)?;

// fn create_and_send_syn_packet(raw_socket: &Socket, source_port: u16, dest_ip: &Ipv4Addr, dest_port: u16) -> std::io::Result<()> {
//    // 3. Create the SYN packet
//     let mut syn_packet = create_syn_packet(source_port, dest_port);
//     println!("SYN packet created");
//     println!("    → Source Port: {}", syn_packet.source_port);
//     println!("    → Destination Port: {}", syn_packet.destination_port);
//     println!("    → Sequence Number: {}", syn_packet.sequence_number);
//     println!("    → SYN Flag: {}", syn_packet.flags_syn);

//     // Compute the TCP checksum
//     syn_packet.checksum = compute_tcp_checksum(&syn_packet, &Ipv4Addr::new(127, 0, 0, 1), dest_ip);
//     println!("TCP checksum computed: 0x{:04x}", syn_packet.checksum);

//     // Construct the complete TCP/IP packet
//     // We use localhost as source IP for now
//     let complete_packet = construct_tcp_ip_packet(&syn_packet, &Ipv4Addr::new(127, 0, 0, 1), dest_ip);
//     println!("Total size: {} bytes", complete_packet.len());
//     println!("First 20 bytes (IP header): {:02x?}", &complete_packet[..20]);
//     println!("Next 20 bytes (TCP header): {:02x?}", &complete_packet[20..40]);

//     // 3. Create destination sockaddr
//     let dest_addr = SockAddr::from(SocketAddr::new((*dest_ip).into(), dest_port));
//     println!("Created destination socket, address: {:?}, port: {}", dest_addr.as_socket_ipv4().unwrap().ip(), dest_addr.as_socket_ipv4().unwrap().port());

//     // 4. Send the SYN packet
//     println!("\n📤 Sending SYN packet...");
//     match raw_socket.send_to(&complete_packet, &dest_addr) {
//         Ok(bytes) => println!("  ✅ Sent {} bytes successfully", bytes),
//         Err(e) => {
//             println!("  ❌ Send failed: {}", e);
//             return Err(e);
//         }
//     }

//     // 5. Wait for response
//     let mut buf = [MaybeUninit::uninit(); 65535];
//     raw_socket.set_read_timeout(Some(Duration::from_millis(1500)))?;

//     // 6. Receive response and return the port state
//     match raw_socket.recv(&mut buf) {
//         Ok(n) if n >= 40 => {
//             println!("  Received {} bytes", n);

//             let received_data = &buf[..n];
//             let buf: Vec<u8> = received_data
//                 .iter()
//                 .map(|b| unsafe { b.assume_init() })
//                 .collect();

//             let ip_header_len = (buf[0] & 0x0f) * 4;
//             let tcp_flags = buf[(ip_header_len + 13) as usize];
//             println!("  TCP Flags received: 0x{:02x}", tcp_flags);

//             Ok(match tcp_flags {
//                 f if f & 0x12 == 0x12 => {
//                     println!("  🟢 Detected: SYN-ACK (Port Open)");
//                     PortState::Open;
//                 }
//                 f if f & 0x04 == 0x04 => {
//                     println!("  🔴 Detected: RST (Port Closed)");
//                     PortState::Closed;
//                 }
//                 _ => {
//                     println!("  🟡 Detected: Unknown response (Port Filtered)");
//                     PortState::Filtered;
//                 }
//             })
//         }
//         Ok(n) => {
//             println!("  Received packet too small: {} bytes", n);
//             Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Received packet too small"))
//         },
//         Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
//             println!("  No response received (timeout)");
//             Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "No response received"))
//         },
//         Err(e) => {
//             println!("  ❌ Error receiving response: {}", e);
//             Err(e)
//         }
// }
// }
