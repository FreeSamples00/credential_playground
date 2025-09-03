// src/main.rs
//! This program simulates a shell with account management tools:
//! * makeuser - create a user
//! * login - log in to a user account
//! * logout - log out of a user account
//! * switchuser - switch to another user account
//! * whoami - print current account name
//! * users - print all registered users
//! * chpass - change account password
//! * chname - change account name
//! * reset - delete all accounts (including root)
//! * clear - clear terminal screen
//! * exit - exit pseudo-shell

// ==================== IMPORTS ====================

mod auth_utils;
use auth_utils::*;
use std::io::{self, Write};

// ==================== CONSTANTS ====================

/// path to file where user data is stored
const STORAGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/userdata.csv");

/// predefined nulluser name
const NULLUSER: &str = "";

/// predefined root user name
const ROOT: &str = "root";

/// help message of commands for any normal user
const USER_HELP_MSG: &str = "help, ?            display this helpful message
logout             logout
switchuser <user>  logout, login as <user>
chpass             change your password
chname             change your username
whoami             print out username
users              list users
clear              clear screen
exit               exit program";

/// help message of commands for the root user
const ROOT_HELP_MSG: &str = "help, ?            display this helpful message
logout             logout
switchuser <user>  logout, login as <user>
chpass <user>      change a user's password
chname <user>      change a user's username
reset              delete all users and clear stored credentials
whoami             print out username
users              list users
clear              clear screen
exit               exit program";

/// help message of commands for a logged out user
const NULL_HELP_MSG: &str = "help, ?            display this helpful message
login <user>       login to an account
makeuser           create root if it does not exist
whoami             print username
users              list user
clear              clear screen
exit               exit program";

// ==================== FUNCTIONS ====================

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

// TODO: send to leyton when done

// TODO: test all commands

// TODO: implement sudo?

// ==================== MAINLOOP ====================

/// This is a pseudo-shell to simulate logins and credential management
fn main() {
    println!("===== ACCOUNT MANAGEMENT SIM =====");

    let mut db: UserCredentials = UserCredentials::new(STORAGE_PATH.into());
    let mut exit_flag: bool = false;
    let mut user: String = NULLUSER.into();

    while !exit_flag {
        let prompt;
        if user == NULLUSER {
            prompt = "$ ".to_string();
        } else {
            prompt = format!("{} $ ", &user);
        }
        let argv: Vec<String> = inline_input(&prompt).split(' ').map(String::from).collect();
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
                if argc != 1 {
                    println!("Invalid arguments for '{}'", argv[0]);
                    continue;
                }
                if user != ROOT {
                    println!("Only root can reset credentials");
                    continue;
                }
                if authenticate(&db, ROOT, &password_input("Root password: ", false)) {
                    if inline_input("Are you sure you wish to delete all user information? [Y/n]: ")
                        .to_lowercase()
                        != "y"
                    {
                        continue;
                    }
                    for username in db.list_users() {
                        db.remove(&username);
                    }
                    user = NULLUSER.into();
                    println!("All user credentials deleted");
                } else {
                    println!("Failed to authenticate as root");
                }
            }
            "rmuser" => {
                if user == ROOT {
                    let username;
                    if argc == 2 {
                        username = argv[1].clone();
                    } else if argc == 1 {
                        username = inline_input("Username: ");
                    } else {
                        println!("Invalid arguments for '{}'", argv[0]);
                        continue;
                    }
                    if authenticate(&db, ROOT, &password_input("Root password: ", false)) {
                        if username == ROOT {
                            println!("Can't delete root");
                            continue;
                        }
                        db.remove(&username);
                        println!("User '{}' deleted", username);
                    } else {
                        println!("Failed to authenticate as root");
                    }
                } else {
                    println!("Only root can delete user accounts");
                }
            }
            "makeuser" => {
                let username;
                if user == NULLUSER {
                    if argc != 1 && argv[1] != ROOT {
                        println!("Invalid arguments for '{}'", argv[0]);
                        continue;
                    }
                    if !db.contains(ROOT) {
                        username = ROOT.to_string();
                        println!("Creating root");
                    } else {
                        println!("Only root can create user accounts");
                        continue;
                    }
                } else if user == ROOT {
                    if argc == 2 {
                        username = argv[1].clone();
                    } else if argc == 1 {
                        username = inline_input("Username: ");
                    } else {
                        println!("Invalid arguments for '{}'", argv[0]);
                        continue;
                    }
                } else {
                    println!("Only root can create user accounts");
                    continue;
                }

                if db.contains(&username) {
                    println!("User '{}' already exists", username);
                    continue;
                }
                let password = password_input("Password: ", true);
                db.set(
                    &username,
                    &hash_password(&password, get_salt(None), DEF_HASH_COST),
                );
                if username == ROOT {
                    user = ROOT.to_string();
                }
                println!("Created user '{}'", username);
            }
            "login" => {
                if user != NULLUSER {
                    println!("Already logged in as {}", user);
                    continue;
                }
                let username;
                if argc == 1 {
                    username = inline_input("Username: ");
                } else if argc == 2 {
                    username = argv[1].clone();
                } else {
                    println!("Invalid arguments for '{}'", argv[0]);
                    continue;
                }
                if authenticate(&db, &username, &password_input("Password: ", false)) {
                    user = username.clone();
                    println!("Logged in as {}", username);
                } else {
                    println!("Failed to authenticate as {}", username);
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
                let username;
                if argc == 2 {
                    username = argv[1].clone();
                } else if argc == 1 {
                    username = inline_input("Username: ");
                } else {
                    println!("Invalid arguments for '{}'", argv[0]);
                    continue;
                }
                if authenticate(&db, &username, &password_input("Password: ", false)) {
                    println!("Logged of of {}, logged in as {}", user, username);
                    user = username.clone();
                } else {
                    println!("Failed to authenticate as {}", username);
                }
            }
            "chpass" => {
                let username;
                if user == ROOT {
                    if argc == 2 {
                        username = argv[1].clone();
                    } else if argc == 1 {
                        username = user.clone();
                    } else {
                        println!("Invalid arguments for '{}'", argv[0]);
                        continue;
                    }
                    if authenticate(&db, &username, &password_input("Root password: ", false)) {
                        db.set(
                            &username,
                            &hash_password(
                                &password_input("New password: ", true),
                                get_salt(None),
                                DEF_HASH_COST,
                            ),
                        );
                        println!("Password changed for {}", username);
                    } else {
                        println!("Failed to authenticate as root");
                        continue;
                    }
                } else if user != NULLUSER {
                    if argc != 1 {
                        println!("Invalid arguments for '{}'", argv[0]);
                        continue;
                    }
                    username = user.clone();
                    if authenticate(&db, &username, &password_input("Current password: ", false)) {
                        db.set(
                            &username,
                            &hash_password(
                                &password_input("New password: ", true),
                                get_salt(None),
                                DEF_HASH_COST,
                            ),
                        );
                        println!("Password changed for {}", username);
                    } else {
                        println!("Failed to authenticate as {}", username);
                    }
                } else {
                    println!("Must be logged in to change password");
                }
            }
            "chname" => {
                let username;
                if user == NULLUSER {
                    println!("Must be logged in to change a username");
                    continue;
                } else if user != ROOT {
                    if argc != 1 {
                        println!("Invalid arguments for '{}'", argv[0]);
                        continue;
                    }
                    username = user.clone();
                    if authenticate(&db, &username, &password_input("Password: ", false)) {
                        let new_username = inline_input("New username: ");
                        if new_username == ROOT {
                            println!("Cannot change username to root");
                            continue;
                        }
                        if db.contains(&new_username) {
                            println!("Account '{}' already exists", new_username);
                            continue;
                        }
                        let hashword = db.get(&username).unwrap().clone();
                        db.remove(&username);
                        db.set(&new_username, &hashword);
                        user = new_username.clone();
                        println!("Changed {} to {}", username, new_username);
                    } else {
                        println!("Failed to authenticate as {}", username);
                    }
                } else {
                    if argc == 2 {
                        username = argv[1].clone();
                    } else if argc == 1 {
                        username = inline_input("Username: ");
                    } else {
                        println!("Invalid arguments for '{}'", argv[0]);
                        continue;
                    }
                    if username == ROOT {
                        println!("Cannot change username of root");
                        continue;
                    }
                    if authenticate(&db, ROOT, &password_input("Root password: ", false)) {
                        let new_username = inline_input("New username: ");
                        if new_username == ROOT {
                            println!("Cannot change username to root");
                            continue;
                        }
                        if db.contains(&new_username) {
                            println!("Account '{}' already exists", new_username);
                            continue;
                        }
                        let hashword = db.get(&username).unwrap().clone();
                        db.remove(&username);
                        db.set(&new_username, &hashword);
                        println!("Changed {} to {}", username, new_username);
                    } else {
                        println!("Failed to authenticate as root");
                    }
                }
            }
            "whoami" => {
                if user == NULLUSER {
                    println!("Not logged in");
                } else {
                    println!("{}", user);
                }
            }
            "users" => {
                for username in db.list_users() {
                    println!("{}", username);
                }
            }
            "clear" => {
                print!("\x1bc"); // ANSI escape code to clear terminal screen
            }
            _ => {
                if argv[0] != "" {
                    println!("Unknown command '{}'", argv[0].trim());
                }
            }
        }
    }
}
