use rand_core::{OsRng, TryRngCore};
use rpassword;
use std::collections::HashMap;
use std::io;

/// default length of salt, in bytes
const DEF_SALT_LEN: usize = 16;

/// default work for hash algo, e.g. 2^n iterations
const DEF_HASH_COST: u8 = 10;

/// maximum length for a password to be hashed by bcrypt in bytes (includes null character)
const MAX_PASS_LEN: u8 = 56;

/// path to file where user data is stored
const STORAGE_PATH: &str = "./userdata.csv";

// TODO: data structure that tracks all users and logins (hashtable?)
// include a list of 'dirty' users where changes are not reflected on disk
// 'sync' function to update disk and vice versa

struct UserCredentials {
    cred_hashmap: HashMap<String, String>,
    dirty_users: Vec<String>,
    storage_location: String,
}

impl UserCredentials {
    pub fn new(filepath: String) -> Self {
        UserCredentials {
            cred_hashmap: Self::read_disk(&filepath),
            dirty_users: Vec::new(),
            storage_location: filepath,
        }
    }

    pub fn list_users() -> Vec<String> {
        todo!("Implement listing users");
    }

    fn read_disk(filepath: &String) -> HashMap<String, String> {
        HashMap::new()
        // TODO: implement storage
    }

    fn write_disk(users: &mut Vec<String>) {
        todo!("Implement writing to disk");
    }

    pub fn contains(&self, username: String) -> bool {
        self.cred_hashmap.contains_key(&username)
    }

    pub fn set(&mut self, username: String, passhash: String) -> &mut Self {
        self.cred_hashmap.insert(username, passhash);
        self
    }

    pub fn get(&self, username: String) -> Option<&String> {
        self.cred_hashmap.get(&username)
    }

    pub fn remove(&mut self, username: String) -> &mut Self {
        self.cred_hashmap.remove(&username);
        self
    }
}

// TODO: implement bcrypt (https://en.wikipedia.org/wiki/Bcrypt)
// output format: $AA$BB$CCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
// A: algorithm identifier ('2a' for bcrypt)
// B: input cost <i32> (2^n rounds)
// C: salt (base 64 encoding)
// D: hash (base 64 encoding of the first 23 bytes of the 24 byte computed hash)

/// This function hashes a given password using a custom implementation of bcrypt
/// **DO NOT USE THIS**, it is not guaranteed to be secure
///
/// # Arguments
/// * `password` - A `String` of at most `MAX_PASS_LEN` bytes to be hashed
/// * `salt` - A `Vec<u8>` of random data to be used as a salt in the hashing process
/// * `cost` - A `u8` value representing the amount of work to be performed (2^`cost` iterations)
///
/// # Return
/// * `String` - Hashed password: `$AA$BB$CCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD`
///     * `A` - the type and version of the hash algorithm
///     * `B` - the `cost` used in the calculations
///     * `C` - the base64 encoded `salt` used in the hash calculation
///     * `D` - the base64 encoding of the resulting password hash
fn hash(password: String, salt: Vec<u8>, cost: u8) -> String {
    // max password length: 72 bytes (UTF-8 encoded)
    //  if less than 72, repeat password and truncate at 72 bytes

    // from these 72 bytes create 18 32-bit 'subkeys'
    return password;
    todo!("Implement hashing");
}

/// This function creates 'num_bytes' bytes of random data to
/// be used as a salt in a cryptographic hash.
///
/// # Arguments
/// * `num_bytes` - usize number of bytes to create
///
/// # Return
/// * `Vec<u8>` - Vector of random data where each element is a byte
fn get_salt(num_bytes: Option<usize>) -> Vec<u8> {
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
    return salt;
}

// TODO: take secured input (use rpassword)
fn secure_inp() -> String {
    todo!("Implement secure input");
}

// TODO: pseudo shell environment for logins etc
// Commands:
// 'help' || '?' - list commands and short description
// 'reset' - clear all saved creds (needs root login)
// 'rmuser' - remove a user by name (needs root or that user login)
// 'makeuser' - create a user, both name and pass (may need root)
// 'login' - login as a specified user (must be logged out)
// 'logout' - logout
// 'switchuser' - logout then login as user
// 'chpass' - as user: change password, as root: change anyone's password
// 'whoami' - printout name of current user
fn main() {
    let mut db: UserCredentials = UserCredentials::new(STORAGE_PATH.into());
    db.set("user".into(), "12345".into());
    match db.get("user".into()) {
        Some(pass) => {
            println!("user: {}", pass);
        }
        None => {
            println!("Error");
        }
    };
    println!("contains 'user': {}", db.contains("user".into()));
    println!("contains 'bob': {}", db.contains("bob".into()));
    db.remove("user".into());
    println!(
        "removed 'user'\ncontains 'user': {}",
        db.contains("user".into())
    );
}
