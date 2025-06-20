use rand_core::{OsRng, TryRngCore};
use rpassword::prompt_password;
use std::collections::HashMap;

/// default length of salt, in bytes
pub const DEF_SALT_LEN: usize = 16;

/// default work for hash algo, e.g. 2^n iterations
pub const DEF_HASH_COST: u8 = 12;

/// maximum length for a password to be hashed by bcrypt in bytes (includes null character)
pub const MAX_PASS_BYTES: u8 = 56;

/// minimum length for a password to be hashed by bcrypt in bytes (includes null character)
pub const MIN_PASS_BYTES: u8 = 8;

/// base-64 encoding alphabet for salts and hashes
pub const ENCODING_ALPHABET: &str =
    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// data structure that holds users and their credentials
/// # Fields
/// * `cred_hashmap` - hashmap that holds credentials
/// * `storage_location` - filepath to where credentials are stored on disk
/// * `dirty_users` - list of users whose credentials have changed since the last write
/// # Methods
/// * `new` - creates data structure
/// * `list_users` - returns a list of all registered users
/// * `contains` - checks for the existence of a user
/// * `set` - creates a user or changes an existing users password
/// * `get` - retrieves a users hashed password if they exist
/// * `remove` - deletes a user from the system
pub struct UserCredentials {
    cred_hashmap: HashMap<String, String>,
    dirty_users: Vec<String>,
    storage_location: String,
}

/// Methods for the struct
impl UserCredentials {
    /// create a new credential struct
    /// # Arguments
    /// * `filepath` - filepath of where credentials are stored on disk
    pub fn new(filepath: String) -> Self {
        UserCredentials {
            cred_hashmap: Self::read_disk(&filepath),
            dirty_users: Vec::new(),
            storage_location: filepath,
        }
    }

    /// internal method to read stored credentials from disk
    /// # Arguments
    /// * `filepath` - path to file
    fn read_disk(filepath: &String) -> HashMap<String, String> {
        HashMap::new()
        // TODO: implement storage
    }

    /// internal method to update credentials on disk
    fn write_disk(&mut self) {
        todo!("Implement writing to disk");
        // TODO: implement file updating
        // - creation if no file
        // - editing if file (for now delete and rewrite)
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

    /// method that registers a user or changes and existing users password
    /// # Arguments
    /// * `username` - account name
    /// * `hashword` - hashed password
    pub fn set(&mut self, username: &str, hashword: &str) -> &mut Self {
        self.cred_hashmap.insert(username.into(), hashword.into());
        self
    }

    /// method that retrieves a users hashed password
    /// # Arguments
    /// * `username` - account name
    /// # Return
    /// * hashed password if it exists
    pub fn get(&self, username: &str) -> Option<&String> {
        self.cred_hashmap.get(username.into())
    }

    /// method that deletes a users record
    /// # Arguments
    /// * `username` - account name
    pub fn remove(&mut self, username: &str) -> &mut Self {
        self.cred_hashmap.remove(username.into());
        self
    }
}

// TODO: implement bcrypt (https://en.wikipedia.org/wiki/Bcrypt)
// output format: $AA$BB$CCCCCCCCCCCCCCCCCCCCCC$DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
// A: algorithm identifier ('2a' for bcrypt)
// B: input cost <i32> (2^n rounds)
// C: salt (base 64 encoding)
// D: hash (base 64 encoding of the first 23 bytes of the 24 byte computed hash)

/// This function hashes a given password using a custom implementation of bcrypt
/// **DO NOT USE THIS**, it is not guaranteed to be secure
/// # Arguments
/// * `password` - password of at most `MAX_PASS_LEN` bytes to be hashed
/// * `salt` - random data to be used as a salt in the hashing process
/// * `cost` - number representing the amount of work to be performed (2^`cost` iterations)
/// # Return
/// * Hashed password: `$AA$BB$CCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD`
///     * `A` - the type and version of the hash algorithm
///     * `B` - the `cost` used in the calculations
///     * `C` - the base64 encoded `salt` used in the hash calculation
///     * `D` - the base64 encoding of the resulting password hash
pub fn hash_password(password: &str, salt: Vec<u8>, cost: u8) -> String {
    // max password length: 72 bytes (UTF-8 encoded)
    //  if less than 72, repeat password and truncate at 72 bytes

    // from these 72 bytes create 18 32-bit 'subkeys'
    return password.into();
    // TODO: implement bcrypt here
}

/// This function creates random data to be used as a salt in a cryptographic hash
/// # Arguments
/// * `num_bytes` - usize number of bytes to create
/// # Return
/// * Vector of random data where each element is a byte
pub fn get_salt(num_bytes: Option<usize>) -> Vec<u8> {
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
            let inp2: String = prompt_password("Confirm password: ").expect("read_password failed");
            if inp1 == inp2 {
                return inp1;
            } else {
                println!("\nPasswords do not match");
            }
        }
    } else {
        prompt_password(prompt).expect("read_password failed")
    }
}

/// Function that authenticates a user
/// # Arguments
/// * `database` - a `UserCredentials` database storing user credentials
/// * `username` - String of users account name
/// * `password` - String of user's password (raw)
/// # Return
/// * whether or not user is authenticated
pub fn authenticate(database: &UserCredentials, username: &str, password: &str) -> bool {
    // TODO: insecure auth for testing, remove
    if !database.contains(username) {
        return false;
    }

    match database.get(username) {
        Some(hashword) => {
            if hashword == password {
                return true;
            } else {
                return false;
            }
        }
        None => {
            return false;
        }
    }

    // TODO: actually implement authentication

    match database.get(username) {
        None => return false,
        Some(hashword) => {
            // array contents: hash info, cost, salt, hashed password
            let userdata: Vec<String> = hashword.split('$').map(String::from).collect();
            assert_eq!(
                userdata.len(),
                4,
                "Improperly formatted hash: '{}'",
                hashword
            );
            let hash_info = userdata[0];
            let cost = userdata[1]
                .parse::<u8>()
                .expect("Failed to parse hash cost");
            let salt = userdata[2];
            let hashword = userdata[3];
        }
    };
}
