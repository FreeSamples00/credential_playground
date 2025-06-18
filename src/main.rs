use rand_core::{OsRng, TryRngCore};
use rpassword::prompt_password;
use std::collections::HashMap;
use std::io::{self, Write};

/// default length of salt, in bytes
const DEF_SALT_LEN: usize = 16;

/// default work for hash algo, e.g. 2^n iterations
const DEF_HASH_COST: u8 = 10;

/// maximum length for a password to be hashed by bcrypt in bytes (includes null character)
const MAX_PASS_LEN: u8 = 56;

/// path to file where user data is stored
const STORAGE_PATH: &str = "./userdata.csv";

/// base-64 encoding alphabet for salts and hashes
const ENCODING_ALPHABET: &str = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// predefined nulluser name
const NULLUSER: &str = "";

// predefined root user name
const ROOT: &str = "root";

/// cost for hashing function
const COST: u8 = 10;

/// help message of commands for any normal user
const USER_HELP_MSG: &str = "
help, ?            Display this helpful message
logout             logout
switchuser <user>  logout, login as <user>
chpass             change your password
chname             change your username
whoami             print out username
users              list users
";

/// help message of commands for the root user
const ROOT_HELP_MSG: &str = "
help, ?            display this helpful message
logout             logout
switchuser <user>  logout, login as <user>
chpass <user>      change a user's password
chname <user>      change a user's username
reset              delete all users and clear stored credentials
whoami             print out username
users              list users
";

/// help message of commands for a logged out user
const NULL_HELP_MSG: &str = "
help, ?            display this helpful message
login <user>       login to an account
rmuser             remove a user
makeuser           make a user
users              list users
";

// TODO: send to leyton

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
struct UserCredentials {
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
fn hash_password(password: String, salt: Vec<u8>, cost: u8) -> String {
    // max password length: 72 bytes (UTF-8 encoded)
    //  if less than 72, repeat password and truncate at 72 bytes

    // from these 72 bytes create 18 32-bit 'subkeys'
    return password;
    // TODO: implement bcrypt here
}

/// This function creates random data to be used as a salt in a cryptographic hash
/// # Arguments
/// * `num_bytes` - usize number of bytes to create
/// # Return
/// * Vector of random data where each element is a byte
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

/// function that securly gets a password input from the user
/// # Arguments
/// * `confirm` - bool, if true user is prompted to confirm password
/// # Return
/// * password entered by user
fn password_input(confirm: bool) -> String {
    if confirm {
        loop {
            let inp1: String = prompt_password("Enter password: ").expect("read_password failed");
            let inp2: String =
                prompt_password("Re-enter password: ").expect("read_password failed");
            if inp1 == inp2 {
                return inp1;
            } else {
                println!("\nPasswords do not match");
            }
        }
    } else {
        prompt_password("Enter password: ").expect("read_password failed")
    }
}

/// function to get inline input from the user
/// # Arguments
/// * `prompt` - &str with which to prompt the user for input
/// # Return
/// * input given by the user
fn inline_input(prompt: &str) -> String {
    let mut input_buffer: String = String::new();
    print!("{}", prompt);
    io::stdout().flush().expect("stdout.flush() failed");
    io::stdin()
        .read_line(&mut input_buffer)
        .expect("stdin.read_line() failed");
    input_buffer.trim().into()
}

/// Function that authenticates a user
/// # Arguments
/// * `database` - a `UserCredentials` database storing user credentials
/// * `username` - String of users account name
/// * `password` - String of user's password (raw)
/// # Return
/// * whether or not user is authenticated
fn authenticate(database: &UserCredentials, username: &String, password: &String) -> bool {
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

// TODO: finish commands

/// This is a pseudo-shell to simulate logins and credential management
fn main() {
    let mut db: UserCredentials = UserCredentials::new(STORAGE_PATH.into());
    let mut exit_flag: bool = false;
    let mut user: String = NULLUSER.into();

    while !exit_flag {
        if user == NULLUSER {
            print!("$ ");
        } else {
            print!("{} $ ", user);
        }
        io::stdout().flush().expect("Failed to flush");

        let argv: Vec<String> = inline_input("").split(' ').map(String::from).collect();
        let argc: i8 = argv.len() as i8;

        match argv[0].trim() {
            "exit" => {
                exit_flag = true;
            }
            "help" | "?" => {
                if user == NULLUSER {
                    println!("{}", NULL_HELP_MSG);
                } else if user == ROOT {
                    println!("{}", ROOT_HELP_MSG);
                } else {
                    println!("{}", USER_HELP_MSG);
                }
            }
            "reset" => {
                todo!("implement reset");
            }
            "rmuser" => {
                // TODO: root vs user behavior
                todo!("implement rmuser");
            }
            "makeuser" => {
                // TODO: implement behavior for root, unable to use if user
                let username;
                if !db.contains(ROOT) {
                    username = ROOT.to_string();
                    println!("Creating root");
                } else if argc == 1 {
                    username = inline_input("Username: ");
                } else if argc == 2 {
                    username = argv[1].clone();
                } else {
                    println!("Invalid arguments for 'makeuser'");
                    break;
                }
                if db.contains(&username) {
                    println!("User '{}' already exists", username);
                    break;
                }
                let password = password_input(true);
                db.set(&username, &hash_password(password, get_salt(None), COST));
                user = username.clone(); // TODO: do not login automatically
                println!("Created user '{}' and logged in", username);
            }
            "login" => {
                if user != NULLUSER {
                    println!("Already logged in");
                    break;
                }
                let username;
                if argc == 1 {
                    username = inline_input("Username: ");
                } else if argc == 2 {
                    username = argv[1].clone();
                } else {
                    println!("Invalid arguments for 'login'");
                    break;
                }
                if authenticate(&db, &username, &password_input(false)) {
                    user = username.clone();
                    println!("Logged in as {}", username);
                } else {
                    println!("Login failed");
                }
            }
            "logout" => {
                if user == NULLUSER {
                    println!("Not logged in");
                } else {
                    println!("Logged out of {}", user);
                    user = NULLUSER.into();
                }
            }
            "switchuser" => {
                todo!("implement switchuser");
            }
            "chpass" => {
                //TODO: different behavior for root
                todo!("implement chpass");
            }
            "chname" => {
                // TODO: different behavior for root
                todo!("implement chname");
            }
            "whoami" => {
                if user == NULLUSER {
                    println!("Not logged in");
                } else {
                    println!("{}", user);
                }
            }
            _ => {
                if argv[0] != "" {
                    println!("Unknown command '{}'", argv[0].trim());
                }
            }
        }
    }
}
