// src/auth_utils.rs
//! This module contains utilites for basic password authentication:
//! * hashing
//! * salting
//! * authentication
//! * secure password input
//! * credential storage

// ==================== IMPORTS ====================

use base64::{Engine as _, engine::general_purpose};
use rand_core::{OsRng, TryRngCore};
use rpassword::prompt_password;
use std::collections::HashMap;
use std::fs::File;
use std::fs::write;
use std::io::BufReader;
use std::io::prelude::*;

// ==================== CONSTANTS ====================

/// default length of salt, in bytes
pub const DEF_SALT_LEN: usize = 16;

/// default work for hash algo, e.g. 2^n iterations
pub const DEF_HASH_COST: usize = 12;

/// version of hashing algorithm
const HASH_VERSION: &str = "sha256iter-1";

/// initial h values for sha256 - first 32bits of fractional portion of square roots of first 8 primes
const SHA_H_INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// initial k values for sha256 - first 32bits of fractional portion of cube roots of first 64 primes
const SHA_K_INITIAL: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// ==================== STRUCTURES ====================

/// data structure that holds users and their credentials
/// # Fields
/// * `cred_hashmap` - hashmap that holds credentials
/// * `storage_location` - filepath to where credentials are stored on disk
/// # Methods
/// * `new` - creates data structure
/// * `list_users` - returns a list of all registered users
/// * `contains` - checks for the existence of a user
/// * `set` - creates a user or changes an existing users password
/// * `get` - retrieves a users hashed password if they exist
/// * `remove` - deletes a user from the system
pub struct UserCredentials {
    cred_hashmap: HashMap<String, String>,
    storage_location: String,
}

/// Methods for the struct
impl UserCredentials {
    /// create a new credential struct
    /// # Arguments
    /// * `filepath` - filepath of where credentials are stored on disk
    pub fn new(filepath: &str) -> Self {
        UserCredentials {
            cred_hashmap: Self::read_disk(&filepath),
            storage_location: filepath.clone(),
        }
    }

    /// internal method to read stored credentials from disk
    /// # Arguments
    /// * `filepath` - path to file
    /// # Return
    /// * hashmap - populated with user credentials, empty if file unable to be read
    fn read_disk(filepath: &String) -> HashMap<String, String> {
        let mut ret_val: HashMap<String, String> = HashMap::new();

        // read database file
        let data: File = match File::open(filepath) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("No database found, continuing with no accounts");
                drop(e);
                return ret_val;
            }
        };

        let reader = BufReader::new(data);
        let mut counter: i32 = 0;

        // parse database
        for record in reader.lines() {
            counter += 1;
            let record = match record {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "\x1b[91mUnable to process line #{} of '{}'. Error: {}\x1b[0m",
                        counter, filepath, e
                    );
                    continue;
                }
            };
            match record.split_once(":") {
                Some((username, hashword)) => {
                    if ret_val.contains_key(username) {
                        eprintln!(
                            "\x1b[91mDuplicate user '{}' found on line #{} of '{}', skipping record.\x1b[0m",
                            username, counter, filepath
                        );
                    } else {
                        ret_val.insert(username.into(), hashword.into());
                    }
                }
                None => {
                    eprintln!(
                        "\x1b[91mInvalid entry in line #{} of '{}'\x1b[0m",
                        counter, filepath
                    );
                }
            };
        }
        ret_val
    }

    /// internal method to update credentials on disk
    fn write_disk(&self) {
        let mut write_buf: String = "".to_string();

        // generate database buffer
        for record in self.list_users() {
            match self.cred_hashmap.get(&record) {
                Some(hash) => {
                    write_buf.push_str(&format!("{}:{}\n", record, hash));
                }
                None => {
                    eprintln!(
                        "\x1b[91mPassword not found for '{}', skipping write.\x1b[0m",
                        record
                    );
                    continue;
                }
            }
        }

        // write to disk
        match write(&self.storage_location, write_buf) {
            Ok(()) => {}
            Err(e) => {
                eprintln!(
                    "\x1b[91mFailed to write to '{}'. Error: {}\x1b[0m",
                    self.storage_location, e
                );
            }
        }
    }

    /// method that lists all registered users
    /// # Return
    /// * Vec<string> - list of all users
    pub fn list_users(&self) -> Vec<String> {
        self.cred_hashmap.keys().cloned().collect()
    }

    /// method that checks if a user is registered
    /// # Arguments
    /// * `username` - account name
    /// # Return
    /// * whether or not user exists
    pub fn contains(&self, username: &str) -> bool {
        self.cred_hashmap.contains_key(username.into())
    }

    /// method that retrieves a users hashed password
    /// # Arguments
    /// * `username` - account name
    /// # Return
    /// * hashed password if it exists
    pub fn get(&self, username: &str) -> Option<&String> {
        self.cred_hashmap.get(username.into())
    }

    /// method that registers a user or changes and existing users password
    /// # Arguments
    /// * `username` - account name
    /// * `hashword` - hashed password
    pub fn set(&mut self, username: &str, hashword: &str) -> &mut Self {
        self.cred_hashmap.insert(username.into(), hashword.into());
        self.write_disk();
        self
    }

    /// method that deletes a users record
    /// # Arguments
    /// * `username` - account name
    pub fn remove(&mut self, username: &str) -> &mut Self {
        self.cred_hashmap.remove(username.into());
        self.write_disk();
        self
    }

    /// method that authenticates a user
    /// # Arguments
    /// * `database` - a `UserCredentials` database storing user credentials
    /// * `username` - String of users account name
    /// * `password` - String of user's password (raw)
    /// # Return
    /// * whether or not user is authenticated
    pub fn authenticate(&mut self, username: &str, password: &str) -> bool {
        if !self.contains(username) {
            return false;
        } else {
            // generate hash to compare
            let entry_string = self.get(username).expect("failed to unwrap username");
            let mut entry_iter = entry_string.split("$");
            entry_iter.next();
            entry_iter.next();
            let cost = entry_iter
                .next()
                .expect("Failed to unwrap slice")
                .parse()
                .expect("failed to unwrap parse");
            let salt = entry_iter.next().expect("failed to unwrap salt");

            let hash = hash_password(password, salt, cost);

            // compare
            return &hash == entry_string;
        }
    }
}

// ==================== FUNCTIONS ====================

/// Wrapper for encoding bytes to base64
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Wrapper for decoding base64 to bytes
fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(s)
}

/// A custom implementation of sha-256 encryption, **NOT SECURE**
/// # Arguments
/// * `message` - message to be encrypted, in byte format (Vec<u8>)
/// # Return
/// * The encrypted message, still in byte format
fn sha256(mut message: Vec<u8>) -> Vec<u8> {
    #![allow(non_snake_case)]

    // initialize hash values
    let mut hs: [u32; 8] = SHA_H_INITIAL.clone();

    // initialize round constants
    let k: [u32; 64] = SHA_K_INITIAL.clone();

    // length calculations
    let L: u64 = (message.len() * 8) as u64;

    // Pre-processing (padding)
    message.push(128_u8); // append '10000000' byte

    while message.len() % 64 != 56 {
        message.push(0_u8);
    }

    // add 64bit BE of length
    for b in L.to_be_bytes() {
        message.push(b);
    }

    let L = message.len() * 8;
    assert_eq!(L % 512, 0); // ensure padding worked

    // break into 512-bit chunks
    for chunk in message.chunks_exact(64) {
        assert_eq!(chunk.len(), 64); // ensure chunk size of 64
        let mut w: [u32; 64] = [0; 64];

        // convert bytes to 32bit words and place in w[]
        let mut i = 0;
        for word in chunk.chunks_exact(4) {
            assert_eq!(word.len(), 4); // ensure chunk size of 4
            let word: [u8; 4] = word.try_into().expect("Could not convert slice to array");
            w[i] = u32::from_be_bytes(word);
            i += 1;
        }

        // "extend" first 16 words to remaining 48 words
        for i in 16..64 {
            let s0: u32 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1: u32 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            // w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            w[i] = w[i - 16].wrapping_add(s0.wrapping_add(w[i - 7].wrapping_add(s1)));
        }

        // init working variables to current hash values
        let mut a = hs[0];
        let mut b = hs[1];
        let mut c = hs[2];
        let mut d = hs[3];
        let mut e = hs[4];
        let mut f = hs[5];
        let mut g = hs[6];
        let mut h = hs[7];

        // compression function main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            // let temp1 = h + s1 + ch + k[i] + w[i];
            let temp1 = h.wrapping_add(s1.wrapping_add(ch.wrapping_add(k[i].wrapping_add(w[i]))));
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            // let temp2 = s0 + maj;
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // add compressed chunk to current hash value
        hs[0] = hs[0].wrapping_add(a);
        hs[1] = hs[1].wrapping_add(b);
        hs[2] = hs[2].wrapping_add(c);
        hs[3] = hs[3].wrapping_add(d);
        hs[4] = hs[4].wrapping_add(e);
        hs[5] = hs[5].wrapping_add(f);
        hs[6] = hs[6].wrapping_add(g);
        hs[7] = hs[7].wrapping_add(h);
    }

    // produce final hash value
    let mut digest: Vec<u8> = Vec::new();
    for i in 0..8 {
        digest.append(&mut hs[i].to_be_bytes().to_vec());
    }
    assert_eq!(digest.len() * 8, 256); // ensure hashed result is 256 bits
    digest
}

/// This function uses a custum implementation of sha-256 to hash a password
/// **DO NOT USE** for real world applications, it is definitely not secure
/// # Arguments
/// * `password` - plaintext password to be hashed
/// * `salt` - base64 encoding of random salt to be used for hashing
/// * `cost` - computational cost of this hashing (2^n iterations)
/// # Return
/// * Hashed password: `$AA$BB$CCCCCCCCCCCCCCCCCCCCCC$DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD$`
///     * `A` - the type and version of the hashing algorithm (sha256iter-1)
///     * `B` - the 'cost' used in calculations (2^n iterations)
///     * `C` - the base64 encoded 'salt' appended before hashing
///     * `D` - the base64 encoded hash of the password
pub fn hash_password(password: &str, salt: &str, cost: usize) -> String {
    let mut message: Vec<u8> = password.as_bytes().to_vec();
    message.append(&mut base64_decode(salt).expect("failed to base64 encode"));

    let mut hash = sha256(message);
    for _ in 1..(1usize << cost) {
        hash = sha256(hash);
    }

    let formatted_password = format!(
        "${}${}${}${}$",
        HASH_VERSION,
        cost,
        salt,
        base64_encode(&hash)
    );
    formatted_password
}

/// This function creates random data to be used as a salt in a cryptographic hash
/// # Arguments
/// * `num_bytes` - usize number of bytes to create
/// # Return
/// * base64 encoded random salt
pub fn get_salt(num_bytes: Option<usize>) -> String {
    let num_bytes = match num_bytes {
        Some(num) => num,
        None => DEF_SALT_LEN,
    };
    let mut salt: Vec<u8> = vec![0u8; num_bytes];
    match OsRng.try_fill_bytes(&mut salt) {
        Ok(_) => {}
        Err(e) => {
            panic!("OsRng failed, {}", e);
        }
    }
    return base64_encode(&salt);
}

/// function that securly gets a password input from the user
/// # Arguments
/// * `prompt` - text to prompt user with for password
/// * `confirm` - if true user is prompted to confirm password
/// # Return
/// * password entered by user
pub fn password_input(prompt: &str, confirm: bool) -> String {
    if confirm {
        loop {
            let inp1: String = prompt_password(prompt).expect("read_password failed");
            let inp2: String =
                prompt_password("confirm password: ").expect("reading password failed");
            if inp1 == inp2 {
                return inp1;
            } else {
                println!("\npasswords do not match");
            }
        }
    } else {
        prompt_password(prompt).expect("reading password failed")
    }
}
