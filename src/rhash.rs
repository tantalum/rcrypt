extern crate crypto;
extern crate rustc_serialize;

use std::io;
use std::io::Read;
use std::iter::repeat;
use std::result::Result;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use rustc_serialize::hex::ToHex;

fn calculate_hash(reader: &mut Read) -> Result<Vec<u8>, io::Error> {
    let mut hash_func = Sha256::new();
    let mut in_buffer = [0;1024];

    loop {
        match reader.read(&mut in_buffer[..])  {
            Ok(n) => {
                if n != 0 {
                    hash_func.input(&in_buffer[0..n]);
                } else {
                    break;
                }
            }
            Err(error) => {
                return Err(error);
            }
        }
    }
    let mut result: Vec<u8> = repeat(0x00).take(hash_func.output_bytes()).collect();
    hash_func.result(&mut result[..]);
    return Ok(result)
}

fn main() {

    match calculate_hash(&mut io::stdin()) {
        Ok(hash_bytes) => { println!("{}", &hash_bytes[..].to_hex()); }
        Err(error)    => { println!("Error: {}", error); }
    }
}
