// TODO: Current implementation is O(2N), according to RFC this can be reduced to O(N)
// where N is the size of the buffer.
pub fn rfc1071_checksum(buffer: &[u8]) -> [u8; 2] {
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
