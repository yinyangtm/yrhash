use std::{fs::File, io::Read};

use clap::{Arg, Command};
use crc32fast::Hasher as Crc32Hasher;
use md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

include!(concat!(env!("OUT_DIR"), "/version.rs"));

fn main() {
    let matches = Command::new("Yinyang Hash Utility (Rust)")
        .version(VERSION)
        .author(AUTHORS)
        .about(DESCRIPTION)
        .arg(Arg::new("file")
            .required(false)
            .help("File to compute the SHA256 hash for"))
        .subcommand(Command::new("-m")
            .about("Specify the algorithm to use for hashing the file")
            .arg(Arg::new("algorithm").required(true))
            .arg(Arg::new("file").required(true)))
        .subcommand(Command::new("-c")
            .about("Compare the hash of two files using the SHA256 algorithm")
            .arg(Arg::new("file1").required(true))
            .arg(Arg::new("file2").required(true)))
        .subcommand(Command::new("-i")
            .about("Compare the hash of a file with the provided hash string using the SHA256 algorithm")
            .arg(Arg::new("file").required(true))
            .arg(Arg::new("string").required(true)))
        .get_matches();

    if let Some(file) = matches.get_one::<String>("file") {
        match compute_hash(file, "sha256") {
            Ok(hash) => println!("SHA256 hash of {} is {}", file, hash),
            Err(e) => eprintln!("Error computing hash: {}", e),
        }
    } else if let Some(matches) = matches.subcommand_matches("-m") {
        let algorithm = matches.get_one::<String>("algorithm").unwrap();
        let file_path = matches.get_one::<String>("file").unwrap();
        match compute_hash(file_path, algorithm) {
            Ok(hash) => println!("{} hash of {} is {}", algorithm.to_uppercase(), file_path, hash),
            Err(e) => eprintln!("Error computing hash: {}", e),
        }
    } else if let Some(matches) = matches.subcommand_matches("-c") {
        let file1 = matches.get_one::<String>("file1").unwrap();
        let file2 = matches.get_one::<String>("file2").unwrap();
        compare_files(file1, file2);
    } else if let Some(matches) = matches.subcommand_matches("-i") {
        let file = matches.get_one::<String>("file").unwrap();
        let hash_string = matches.get_one::<String>("string").unwrap().to_lowercase();
        compare_file_hash(file, &hash_string);
    } else {
        eprintln!("No command specified. Use -h for help.");
    }
}

fn compute_hash(file_path: &str, algorithm: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let hash_string = match algorithm {
        "md5" => {
            let digest = md5::compute(&buffer);
            format!("{:x}", digest)
        },
        "sha1" => {
            let digest = Sha1::digest(&buffer);
            digest.iter().map(|byte| format!("{:02x}", byte)).collect()
        },
        "sha256" => {
            let digest = Sha256::digest(&buffer);
            digest.iter().map(|byte| format!("{:02x}", byte)).collect()
        },
        "sha384" => {
            let digest = Sha384::digest(&buffer);
            digest.iter().map(|byte| format!("{:02x}", byte)).collect()
        },
        "sha512" => {
            let digest = Sha512::digest(&buffer);
            digest.iter().map(|byte| format!("{:02x}", byte)).collect()
        },
        "crc32" => {
            let mut hasher = Crc32Hasher::new();
            hasher.update(&buffer);
            format!("{:x}", hasher.finalize())
        },
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unsupported algorithm")),
    };

    Ok(hash_string)
}


fn compare_files(file1_path: &str, file2_path: &str) {
    let hash1 = compute_hash(file1_path, "sha256").unwrap();
    let hash2 = compute_hash(file2_path, "sha256").unwrap();
    if hash1 == hash2 {
        println!("Files are identical.");
        println!("{}", hash1);
    } else {
        println!("Files are different.");
        println!("{} : {}",file1_path, hash1);
        println!("{} : {}",file2_path, hash2);
    }
}

fn compare_file_hash(file_path: &str, comparison_hash: &str) {
    let file_hash = compute_hash(file_path, "sha256").unwrap();
    if file_hash == comparison_hash {
        println!("File hash matches the provided hash.");
    } else {
        println!("File hash does not match the provided hash.");
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    const FILE_PATH: &str = "tests/data/test_file.txt";

    #[test]
    fn test_compute_hash_crc32() {
        let expected_hash = "84bea5a9";
        let computed_hash = compute_hash(FILE_PATH, "crc32").expect("Failed to compute hash");
        assert_eq!(computed_hash, expected_hash, "CRC32 hash does not match the expected value");
    }

    #[test]
    fn test_compute_hash_md5() {
        let expected_hash = "2241c055fa19c9669cfb1aa11f0d19b4";
        let computed_hash = compute_hash(FILE_PATH, "md5").expect("Failed to compute hash");
        assert_eq!(computed_hash, expected_hash, "MD5 hash does not match the expected value");
    }

    #[test]
    fn test_compute_hash_sha1() {
        let expected_hash = "6c3e2239b3c250dc63fafbafa1397994447cff00";
        let computed_hash = compute_hash(FILE_PATH, "sha1").expect("Failed to compute hash");
        assert_eq!(computed_hash, expected_hash, "SHA1 hash does not match the expected value");
    }

    #[test]
    fn test_compute_hash_sha256() {
        let expected_hash = "b7ee49f979327f16328b93d41754c4d9d0d1f06c762ebadb2c7d2e734c3d3c87";
        let computed_hash = compute_hash(FILE_PATH, "sha256").expect("Failed to compute hash");
        assert_eq!(computed_hash, expected_hash, "SHA256 hash does not match the expected value");
    }

    #[test]
    fn test_compute_hash_sha384() {
        let expected_hash = "30f7fada4c5706fc05869a7e3fc666a0a5b8e4409a0222f231c9e756b088a1ccc0e128c36bdeee4f3063e6ec834cdecf";
        let computed_hash = compute_hash(FILE_PATH, "sha384").expect("Failed to compute hash");
        assert_eq!(computed_hash, expected_hash, "SHA384 hash does not match the expected value");
    }

    #[test]
    fn test_compute_hash_sha512() {
        let expected_hash = "3926f31ef4e2097d77eb6c4646c6957c7943f13e74cc8823f2024dd15eaab015c0282ee836a733d31b04a4efc4e471adf914759a0fa4f1fb5fd5233d5b9697eb";
        let computed_hash = compute_hash(FILE_PATH, "sha512").expect("Failed to compute hash");
        assert_eq!(computed_hash, expected_hash, "SHA512 hash does not match the expected value");
    }
}
