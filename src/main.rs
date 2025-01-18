use std::env;
mod types;
use types::TcpHeader;

const DEFAULT_PORT: u16 = 80;

//
// macro_rules! print_mem_offset_bits {
//     ( $field:expr , $struct_name:ty , $field_name:expr) => {
//         {
//                 let header_offset = std::mem::offset_of!($struct_name, $field_name) * 8;
//                 let header_row = header_offset / 32;
//                 let header_column = header_offset % 32;
//                 println!("{}:\t\theader_offset {} \t\trow {},\t\toffset {}", $field, header_offset, header_row, header_column)

//         }
//     };
// }
// Example usage:
// print_mem_offset_bits!("source_port", TcpHeader, source_port);
#[allow(clippy::too_many_arguments)]
fn create_tcp_packet(
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    header_offset: u8,
    reserved: u8,
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
    // TODOs:
    // - make sure the checksum is correctly computed
    TcpHeader {
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number: 0,
        header_offset,
        reserved,
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

fn create_syn_packet(source_port: u16, destination_port: u16, sequence_number: u32) -> TcpHeader {
    create_tcp_packet(
        source_port,
        destination_port,
        sequence_number,
        0,
        0,
        false,
        false,
        false,
        false,
        true,
        false,
        0,
        0,
        0,
        vec![0],
    )
}

fn pack_tcp_header(header: TcpHeader) -> Vec<u8> {
    // Initial capacity should be 24 bytes plus 4 bytes for each option
    let mut packed_header = Vec::with_capacity(24 + 4 * header.options.len());
    packed_header.extend_from_slice(&header.source_port.to_be_bytes());
    packed_header.extend_from_slice(&header.destination_port.to_be_bytes());
    packed_header.extend_from_slice(&header.sequence_number.to_be_bytes());
    // First do left shift of header_offset by 4 bits then or with reserved
    let header_offset_and_reserved = (header.header_offset << 4) | header.reserved;
    packed_header.extend_from_slice(&header_offset_and_reserved.to_be_bytes());
    // Next process the flags with bitwise operations stacking them in a u8
    let flags = (header.flags_urg as u8) << 7
        | (header.flags_ack as u8) << 6
        | (header.flags_psh as u8) << 5
        | (header.flags_rst as u8) << 4
        | (header.flags_syn as u8) << 3
        | (header.flags_fin as u8) << 2;
    packed_header.extend_from_slice(&flags.to_be_bytes());
    // Next process the window
    packed_header.extend_from_slice(&header.window.to_be_bytes());
    // Next process the checksum
    packed_header.extend_from_slice(&header.checksum.to_be_bytes());
    // Next process the urgent pointer
    packed_header.extend_from_slice(&header.urgent_pointer.to_be_bytes());
    // Next process the options
    // Add options to the end of the packed header casting options to u8 and convert to big endian bytes
    packed_header.extend_from_slice(
        &header
            .options
            .iter()
            .flat_map(|o| o.to_be_bytes())
            .collect::<Vec<u8>>(),
    );
    packed_header
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

fn main() {
    // Collecting the command line arguments into a vector and printing them
    let args: Vec<String> = env::args().collect();

    // DEBUG CODE, remove later
    let syn_packet = create_syn_packet(60401, 80, 598238115);
    let packed_syn_packet = pack_tcp_header(syn_packet);
    println!("{:#04x?}", packed_syn_packet);

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
