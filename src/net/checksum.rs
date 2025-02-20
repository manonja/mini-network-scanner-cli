// TODO: Current implementation is O(2N), according to RFC this can be reduced to O(N)
// where N is the size of the buffer.
pub fn rfc1071_checksum(buffer: &[u8]) -> [u8; 2] {
    // Create a vector that will hold an even number of bytes
    let mut bytes_be = buffer.iter().map(|&a| a.to_be()).collect::<Vec<_>>();

    // If we have an odd number of bytes, pad with a zero
    if bytes_be.len() % 2 != 0 {
        bytes_be.push(0);
    }

    // Process 16-bit words
    let mut sum: u32 = bytes_be
        .chunks_exact(2)
        .map(|chunk| ((chunk[0] as u32) << 8) | (chunk[1] as u32))
        .sum();

    // Add carried bits
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take one's complement
    let checksum = !sum as u16;

    println!("checksum for buffer computed: {:04x}", checksum);

    checksum.to_be_bytes()
}
