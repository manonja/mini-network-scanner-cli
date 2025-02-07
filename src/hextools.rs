use std::{
    fs::File,
    io::{self, Write},
};

pub fn format_hexdump(data: &[u8]) -> String {
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
pub fn dump_hex_file(buffer: Vec<u8>) -> io::Result<()> {
    // Example buffer with some binary data
    // let buffer: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];

    // Create (or overwrite) a file named "dump.bin"
    let mut file = File::create("dump.bin")?;

    // Write the entire buffer to the file
    file.write_all(&buffer)?;

    println!("Buffer dumped to dump.bin");
    Ok(())
}
