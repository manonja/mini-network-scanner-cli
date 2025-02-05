use socket2::Protocol;
use socket2::{Domain, Socket, Type};
use std::env;
use std::io;

use std::time::Duration;

use std::fs::File;
use std::io::Write;

use std::mem::MaybeUninit;
use std::net::SocketAddr;
mod types;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use types::{Ipv4Header, TcpHeader};

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

impl TcpHeader {
    fn pack(self: &mut TcpHeader) -> Vec<u8> {
        // The TCP self length is 20 bytes, plus 4 bytes for each option
        let self_length_in_32_bit_words = 5 + self.options.capacity();
        let mut buffer = Vec::with_capacity(self_length_in_32_bit_words * 4);

        // Store checksum value and temporarily set to 0 for calculation
        let original_checksum = self.checksum;
        self.checksum = 0;

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
        let offset_and_reserved: u8 = (self_length_in_32_bit_words as u8) << 4;
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

        // Calculate checksum if not already set
        if original_checksum == 0 {
            self.checksum = u16::from_be_bytes(rfc1071_checksum(&buffer));
            // Update checksum in buffer directly
            buffer[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        } else {
            // Restore original checksum
            self.checksum = original_checksum;
            buffer[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        }

        buffer
    }
}

// TODO: Current implementation is O(2N), according to RFC this can be reduced to O(N)
// where N is the size of the buffer.
fn rfc1071_checksum(buffer: &[u8]) -> [u8; 2] {
    let bytes_be = buffer.iter().map(|&a| a.to_be()).collect::<Vec<_>>();
    let bytes_be_chunked: Vec<Vec<u8>> = bytes_be.chunks(2).map(|c| c.to_vec()).collect();
    let words16 = bytes_be_chunked
        .into_iter()
        .map(|db| (db[0] as u32) << 8 | (db[1] as u32));
    let words_sum: u32 = words16.sum();
    let carry: u16 = ((words_sum / 0xffff) % 10).try_into().unwrap();
    let first_four_digits: u16 = (words_sum & 0xffff).try_into().unwrap();
    let carry_addition: u16 = first_four_digits + carry;
    let checksum = !carry_addition;

    println!("checksum for buffer computed: {:02x?}", checksum);

    checksum.to_be_bytes()
}
/// Creates an IPv4 packet with the given parameters
fn create_ip_packet(
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
    fn pack(self: &mut Ipv4Header) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(20);

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

        println!(
            "IP header created: {:02x?} with checksum: 0x{:04x}",
            buffer, self.checksum
        );

        buffer
    }
}

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

    {program_name} -- --scan <ip_address>:<port>  --src <source_ip>
    {program_name} -s <ip_address>:<port> -r <source_ip>

    Examples:
    {program_name} -- --scan 127.0.0.1:80 --src 127.0.0.1        # Scans port 80 on localhost
    


************************************************************************************************
", );
    println!("{}", help_message);
}

// Construct the complete TCP/IP packet
fn construct_ip_package_for_tcp_header(
    tcp_header: &mut TcpHeader,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
) -> Vec<u8> {
    // First create the TCP header with checksum
    let tcp_packet = tcp_header.pack();

    println!("TCP_PACKET SYN CONSTRUCT IP PACKAGE 0x{:02x?}", tcp_packet);

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

    //     println!("Total size: {} bytes", complete_packet.len());
    //     println!("First 20 bytes (IP header): {:02x?}", &complete_packet[..20]);
    //     println!("Next 20 bytes (TCP header): {:02x?}", &complete_packet[20..40]);

    // Add TCP header and data
    packet.extend_from_slice(&tcp_packet);

    println!("Full IP package       {:02x?}", packet);

    packet
}

// Define our port states
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

    test_checksum_with_wikipedia_example();
    test_tcp_header_pack();
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

    // 2. Set IP_HDRINCL using socket2's built-in method.
    raw_socket.set_header_included_v4(true)?;
    println!("IP_HDRINCL set successfully.");

    let lowest_listen_port = 1024;
    let source_port = rand::thread_rng().gen_range(lowest_listen_port..u16::MAX);
    let raw_socket_address = SocketAddr::new(IpAddr::V4(*source_ip), source_port);
    let socket_at_destination = SocketAddr::new(IpAddr::V4(*destination_ip), destination_port);
    println!("We will try to bind to port {:?}", source_port);
    println!("Socket address and port: {:?}", raw_socket_address);

    let socket_at_destination = socket_at_destination.into();

    // 3. Connect to raw_socket
    raw_socket.connect(&socket_at_destination)?;
    println!(
        "We should be connected to {}:{}, let's check... ",
        destination_ip, destination_port
    );

    match raw_socket.peer_addr() {
        Ok(_) => println!("We are connected to the socket 🚀"),
        Err(error) => println!(
            "Oups, we could not connect to the socket due to error 😵: {}",
            error
        ),
    }

    // 4. Create the TCP SYN package
    let mut syn_packet = create_syn_packet(source_port, destination_port);
    // 5. Add the IP header to the TCP Package
    let ip_syn_package =
        construct_ip_package_for_tcp_header(&mut syn_packet, source_ip, destination_ip);

    println!("Let's send our package 🚀");

    // 5. Set a read timeout so we don't block forever.
    raw_socket.set_read_timeout(Some(Duration::from_secs(10)))?;

    // 6. Receive a response.
    // We'll allocate a buffer for receiving data.
    const BUFFER_SIZE: usize = 100;

    // 7. Create a buffer of unitialised bytes
    let mut recv_buffer: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); BUFFER_SIZE];
    println!("Starting to receive for an answer...👂");

    let send_buffer = ip_syn_package.as_slice();
    println!("{}", format_hexdump(send_buffer));
    let send_result = raw_socket.send(send_buffer);

    match send_result {
        Ok(_) => println!("Successfully sent"),
        Err(error) => println!("OOps 💩: {}", error),
    }

    loop {
        println!("try to receive");
        let res = raw_socket.recv(&mut recv_buffer[..]);
        println!("Maybe received...");

        // 8. Call recv() on our raw socket
        match res {
            Ok(received) => {
                if received == 0 {
                    println!("I continue!!");

                    continue; //nothing received, try again
                }
                let buf: &[u8] = unsafe {
                    std::slice::from_raw_parts(recv_buffer.as_ptr() as *const u8, received)
                };
                println!("Received {} bytes: {:02x?}", received, buf);

                // 9. Parse the IP header to determine where the TCP header starts
                if received < 20 {
                    // not a full IP header, continue parsing
                    println!("Not a full IP Header yet, I continue! !");
                    continue;
                }

                let ip_header_len = (buf[0] & 0x0f) * 4; // IP header length in bytes
                if received < (ip_header_len as usize + 20) {
                    // Not enough bytes for a TCP header; continue waiting.
                    println!("Not enough bytes for a TCP header, I continue! !");
                    continue;
                }

                // The TCP header starts immediately after the IP header
                let tcp_header = &buf[ip_header_len as usize..];
                // Considering the TCP layout:
                // Bytes 0-1: source port, 2-3: dest port, 4-7: sequence number,
                // 8-11: ack number, 12: data offset/reserved, 13: flags, etc.
                let tcp_flags = tcp_header[13];
                println!("TCP flags: 0x{:02x}", tcp_flags);

                // 10. Interprect the flags
                // If we receive a SYN+ACK (SYN = 0x02 and ACK = 0x10), the port is open
                if tcp_flags & 0x12 == 0x12 {
                    println!("Port {} is OPEN 🟢 (SYN+ACK received).", destination_port);
                    return Ok(PortState::Open);
                }
                // If we receive a RST (Reset flag 0x04) then the port is closed.
                else if tcp_flags & 0x04 == 0x04 {
                    println!("Port {} is CLOSED 🔴 (RST received).", destination_port);
                    return Ok(PortState::Closed);
                }
                // Otherwise, the response is not conclusive; break or return filtered.
                else {
                    println!(
                        "Port {} response unknown 🟡. Marking as filtered.",
                        destination_port
                    );
                    return Ok(PortState::Filtered);
                }
            }
            Err(e) => {
                // If the error is a timeout (WouldBlock or TimedOut), assume no response.
                println!("Receive error: {}", e);
                //return Ok(PortState::Filtered);
            }
        }
    }
}

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

fn test_checksum_with_wikipedia_example() {
    // The Wikipedia example IP header (without the checksum field)
    let ip_header: [u8; 18] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xc0, 0xa8, 0x00, 0x01, 0xc0,
        0xa8, 0x00, 0xc7,
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

fn format_hexdump(data: &[u8]) -> String {
    let mut result = String::new();
    let chunks = data.chunks(16);

    for (i, chunk) in chunks.enumerate() {
        // Address column
        result.push_str(&format!("0x{:04x}:  ", i * 16));

        // Hex representation
        for (j, byte) in chunk.iter().enumerate() {
            result.push_str(&format!("{:02x}", byte));

            // Add space after every byte, and an extra space after 8 bytes
            if j < chunk.len() - 1 {
                result.push(' ');
                if j == 7 {
                    result.push(' ');
                }
            }
        }

        // Padding for incomplete lines to align ASCII section
        if chunk.len() < 16 {
            let padding = (16 - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
            result.push_str(&" ".repeat(padding));
        }

        // ASCII representation
        result.push_str("  ");
        for &byte in chunk {
            if byte.is_ascii_graphic() {
                result.push(byte as char);
            } else {
                result.push('.');
            }
        }

        result.push('\n');
    }

    result
}

#[allow(dead_code)]
fn dump_hex_file(buffer: Vec<u8>) -> io::Result<()> {
    // Example buffer with some binary data
    // let buffer: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];

    // Create (or overwrite) a file named "dump.bin"
    let mut file = File::create("dump.bin")?;

    // Write the entire buffer to the file
    file.write_all(&buffer)?;

    println!("Buffer dumped to dump.bin");
    Ok(())
}
