use socket2::Protocol;
use socket2::{Domain, Socket, Type};

use std::time::Duration;

use std::mem::MaybeUninit;
use std::net::SocketAddr;

use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};

use crate::net::ip::construct_ip_package_for_tcp_header;
use crate::net::tcp::create_syn_packet;

use crate::hextools::*;

// Define our port states
#[derive(Debug)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Processes a received packet buffer and, if valid, returns a PortState.
/// Returns `None` if the packet is incomplete or is our own echoed packet.
fn process_received_packet(
    buf: &[u8],
    source_ip: &Ipv4Addr,
    destination_port: u16,
    our_source_port: u16,
) -> Option<PortState> {
    // Ensure we have at least the minimum IP header length.
    if buf.len() < 20 {
        println!("Not a full IP header yet, skipping.");
        return None;
    }

    // Extract the source IP from the IP header (bytes 12-15).
    let received_source_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);

    // Determine IP header length (in bytes)
    let ip_header_len = (buf[0] & 0x0f) * 4;
    if buf.len() < (ip_header_len as usize + 20) {
        println!("Not enough bytes for a TCP header, skipping.");
        return None;
    }

    // The TCP header follows immediately after the IP header.
    let tcp_header = &buf[ip_header_len as usize..];
    let received_dest_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);

    if received_source_ip != *source_ip {
        println!("Not from target IP: {}, skipping", source_ip);
        return None;
    }

    if received_dest_port != our_source_port {
        println!(
            "Packet not destined for our ephemeral port {} (got {}) - skipping.",
            our_source_port, received_dest_port
        );
        return None;
    }

    let tcp_flags = tcp_header[13];
    println!("TCP flags: 0x{:02x}", tcp_flags);

    // Check the flags.
    if tcp_flags & 0x12 == 0x12 {
        println!("Port {} is OPEN 🟢 (SYN+ACK received).", destination_port);
        Some(PortState::Open)
    } else if tcp_flags & 0x04 == 0x04 {
        println!("Port {} is CLOSED 🔴 (RST received).", destination_port);
        Some(PortState::Closed)
    } else {
        println!(
            "Port {} response unknown 🟡. Marking as filtered.",
            destination_port
        );
        Some(PortState::Filtered)
    }
}

pub fn tcp_syn_scan(
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

    // 5. Set a read timeout so we don't block forever.
    raw_socket.set_read_timeout(Some(Duration::from_secs(10)))?;

    // 6. Receive a response.
    // We'll allocate a buffer for receiving data.
    const BUFFER_SIZE: usize = 100;

    // 7. Create a buffer of unitialised bytes
    let mut recv_buffer: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); BUFFER_SIZE];

    let send_buffer = ip_syn_package.as_slice();

    println!("Let's send our package 🚀, here is what we will send");
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
            Ok(num_bytes_received) => {
                if num_bytes_received == 0 {
                    println!("No data received, I continue!!");

                    continue; //nothing received, try again
                }
                let buf: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        recv_buffer.as_ptr() as *const u8,
                        num_bytes_received,
                    )
                };
                println!("Received {}", num_bytes_received);
                println!("{}", format_hexdump(buf));

                // 9. Parse the IP header to determine where the TCP header starts
                if num_bytes_received < 20 {
                    // not a full IP header, continue parsing
                    println!("Not a full IP Header yet, I continue! !");
                    continue;
                }

                // Process the received packet.
                if let Some(port_state) =
                    process_received_packet(buf, source_ip, destination_port, source_port)
                {
                    return Ok(port_state);
                }
                // Otherwise, keep waiting.

                // let ip_header_len = (buf[0] & 0x0f) * 4; // IP header length in bytes
                // if num_bytes_received < (ip_header_len as usize + 20) {
                //     // Not enough bytes for a TCP header; continue waiting.
                //     println!("Not enough bytes for a TCP header, I continue! !");
                //     continue;
                // }

                // // The TCP header starts immediately after the IP header
                // let tcp_header = &buf[ip_header_len as usize..];
                // // Considering the TCP layout:
                // // Bytes 0-1: source port, 2-3: dest port, 4-7: sequence number,
                // // 8-11: ack number, 12: data offset/reserved, 13: flags, etc.
                // let tcp_flags = tcp_header[13];
                // println!("TCP flags: 0x{:02x}", tcp_flags);

                // // 10. Interprect the flags
                // // If we receive a SYN+ACK (SYN = 0x02 and ACK = 0x10), the port is open
                // if tcp_flags & 0x12 == 0x12 {
                //     println!("Port {} is OPEN 🟢 (SYN+ACK received).", destination_port);
                //     return Ok(PortState::Open);
                // }
                // // If we receive a RST (Reset flag 0x04) then the port is closed.
                // else if tcp_flags & 0x04 == 0x04 {
                //     println!("Port {} is CLOSED 🔴 (RST received).", destination_port);
                //     return Ok(PortState::Closed);
                // }
                // // Otherwise, the response is not conclusive; break or return filtered.
                // else {
                //     println!(
                //         "Port {} response unknown 🟡. Marking as filtered.",
                //         destination_port
                //     );
                //     return Ok(PortState::Filtered);
                // }
            }
            Err(e) => {
                // If the error is a timeout (WouldBlock or TimedOut), assume no response.
                println!("Receive error: {}", e);
                //return Ok(PortState::Filtered);
            }
        }
    }
}
