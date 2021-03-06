extern crate crypto;
extern crate rustc_serialize;

use std::env;
use std::io;
use std::io::Read;
use std::io::Error;
use std::fs::File;
use std::boxed::Box;
use std::iter::repeat;
use std::result::Result;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use rustc_serialize::hex::ToHex;

struct FileReader<> {
    reader:  Box<Read>,
    filename: String
}

struct FileHash {
    hash: Vec<u8>,
    filename: String
}

/// Read the contents of a reader and output either an error or a Vec of bytes
/// that are the SHA256 hash of the readers contents
///
/// # Examples
/// ```
/// let freader = FileReader {reader: Box::new(io::stdin()), filename: "-".to_string()};
/// let hash_result = calculate_hash(&mut freader);
/// ```
fn calculate_hash(freader: &mut FileReader) -> Result<FileHash, Error> {
    let mut hash_func = Sha256::new();
    let mut in_buffer = [0;1024];

    loop {
        match freader.reader.read(&mut in_buffer[..])  {
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
    return Ok(FileHash{hash:result, filename: freader.filename.clone()})
}

fn main() {

    let args: Vec<String> = env::args().collect();
    let file_names = &args[1..];

    let file_readers: Vec<Result<FileReader, Error>> = if file_names.is_empty() {
        vec![Ok(FileReader {reader: Box::new(io::stdin()), filename: "-".to_string()})]
    } else {
        file_names.iter().map(|fname| match File::open(fname) {
            Ok(reader) => {Ok(FileReader{reader: Box::new(reader), filename: fname.to_string()})}
            Err(err) => {Err(err)}
        }).collect()
    };

    let file_hashes: Vec<Result<FileHash, Error>> = file_readers
        .into_iter()
        .map(|read_result| read_result.and_then(|mut freader| calculate_hash(&mut freader)))
        .collect();

    for fhash_result in file_hashes.iter() {
        match fhash_result {
            Ok(fhash) => {println!("{}\t{}", &fhash.hash[..].to_hex(), fhash.filename);}
            Err(err) => {println!("Error: {}", err)}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FileReader;
    use super::calculate_hash;

    use std::boxed::Box;
    use rustc_serialize::hex::ToHex;

    fn assert_hash(value: &'static str, expected_hash: &str) {
        let value_bytes = value.as_bytes();
        let mut freader = FileReader {
            reader: Box::new(value_bytes),
            filename: "test.txt".to_string()
        };
        match calculate_hash(&mut freader) {
            Ok(fhash) => {assert_eq!(&fhash.hash[..].to_hex(), expected_hash)}
            Err(err) => {panic!("Hash should have completed successfully: {}", err)}
        }
    }

    #[test]
    fn hash_hello() {
        assert_hash("Hello, World", "03675ac53ff9cd1535ccc7dfcdfa2c458c5218371f418dc136f2d19ac1fbe8a5");
    }
    
    #[test]
    fn hash_hello_hash() {
        assert_hash("03675ac53ff9cd1535ccc7dfcdfa2c458c5218371f418dc136f2d19ac1fbe8a5", "7a9fe01e98ba53e25bc7e78993d000bee0d83dbfa9d2a273a3a444912281c8ba");
    }

    #[test]
    fn hash_hello_nl() {
        assert_hash("Hello, World\n", "8663bab6d124806b9727f89bb4ab9db4cbcc3862f6bbf22024dfa7212aa4ab7d");
    }
}
