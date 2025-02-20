use scan::tcp_syn_scan;
use std::env;
use std::net::Ipv4Addr;

mod hextools;
mod net; // This declares the module
mod scan;

/// Help for the main program
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

    tcp_syn_scan(&source_ip, &dest_ip, destination_port)?;
    println!("Scan complete");

    Ok(())
}
