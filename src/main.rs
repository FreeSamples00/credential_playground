// src/main.rs

// ==================== IMPORTS ====================

mod auth_utils;
use auth_utils::*;
use std::io::{self, Write};

// ==================== CONSTANTS ====================

/// path to file where user data is stored
const STORAGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/passwd");

/// predefined nulluser name
const NULLUSER: &str = "";

/// predefined root user name
const ROOT: &str = "root";

/// Permission levels
const P_NONE: u8 = 0;
const P_USER: u8 = 1;
const P_SUDO: u8 = 2;
const P_ROOT: u8 = 3;

// ==================== HELPERS ====================

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

// ==================== STRUCTURES ====================

struct Command {
    name: &'static str,
    usage: &'static str,
    description: &'static str,
    permissions: u8,
    handler: fn(&mut Environment, u8, &[String]) -> i8,
}

struct Environment {
    user: String,
    permissions: u8,
    commands: Vec<&'static Command>,
    database: UserCredentials,
}

// ==================== COMMANDS ====================

// ==== HELP ====
#[allow(unused_variables)]
fn f_help(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    let cmds: Vec<&Command> = env
        .commands
        .iter()
        .copied()
        .filter(|c| env.permissions >= c.permissions)
        .collect();

    let mut max_usage_size: usize = 0;
    for cmd in &cmds {
        if cmd.usage.len() > max_usage_size {
            max_usage_size = cmd.usage.len();
        }
    }

    println!("available commands:");
    for cmd in &cmds {
        println!("{:<max_usage_size$}  {}", cmd.usage, cmd.description);
    }
    0
}

static HELP: Command = Command {
    name: "help",
    usage: "help",
    description: "display this helpful message",
    permissions: P_NONE,
    handler: f_help,
};

// ==== WHOAMI ====
#[allow(unused_variables)]
fn f_whoami(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    if env.user == NULLUSER {
        println!("not logged in");
    } else {
        println!("{}", env.user);
    }
    0
}

static WHOAMI: Command = Command {
    name: "whoami",
    usage: "whoami",
    description: "print username",
    permissions: P_NONE,
    handler: f_whoami,
};

// ==== MAKEUSER ====
#[allow(unused_variables)]
fn f_mkuser(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    if argc != 2 {
        println!("invalid arguments for {}", argv[0]);
        1
    } else {
        if env.database.contains(&argv[1]) {
            println!("account {} already exists", argv[1]);
            1
        } else {
            env.database.set(
                &argv[1],
                &hash_password(
                    &password_input("Password: ", true),
                    &get_salt(None),
                    DEF_HASH_COST,
                ),
            );
            println!("created account {}", argv[1]);
            0
        }
    }
}

static MKUSER: Command = Command {
    name: "mkuser",
    usage: "mkuser <username>",
    description: "create a user account",
    permissions: P_ROOT,
    handler: f_mkuser,
};

// ==== USERS ====
#[allow(unused_variables)]
fn f_users(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    for username in env.database.list_users() {
        println!("{}", username);
    }
    0
}

static USERS: Command = Command {
    name: "users",
    usage: "users",
    description: "list all users",
    permissions: P_NONE,
    handler: f_users,
};

// ==== CLEAR ====
#[allow(unused_variables)]
fn f_clear(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    print!("\x1bc"); // ANSI escape code to clear terminal screen
    0
}

static CLEAR: Command = Command {
    name: "clear",
    usage: "clear",
    description: "clear the screen",
    permissions: P_NONE,
    handler: f_clear,
};

// ==== CHNAME ====
#[allow(unused_variables)]
fn f_chname(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    if env.permissions >= P_ROOT {
        if argc != 3 {
            println!("invalid arguments for {} as root", argv[0]);
            1
        } else {
            if authenticate(
                &env.database,
                ROOT,
                &password_input("root password: ", false),
            ) {
                let old_name = &argv[1];
                let new_name = &argv[2];
                if env.database.contains(new_name) {
                    println!("account {} already exists", new_name);
                    return 1;
                }
                if !env.database.contains(old_name) {
                    println!("account {} not found", old_name);
                    return 1;
                }
                let hashword = env.database.get(old_name).unwrap().clone();
                env.database.remove(old_name);
                env.database.set(new_name, &hashword);
                0
            } else {
                println!("could not authenticate as root");
                1
            }
        }
    } else {
        if argc != 2 {
            println!("invalid arguments for {}", argv[0]);
            1
        } else {
            if authenticate(
                &env.database,
                &env.user,
                &password_input("password: ", false),
            ) {
                let old_name = &env.user;
                let new_name = &argv[1];
                if env.database.contains(new_name) {
                    println!("account {} already exists", new_name);
                    return 1;
                }
                if !env.database.contains(old_name) {
                    println!("account {} not found", old_name);
                    return 1;
                }
                let hashword = env.database.get(old_name).unwrap().clone();
                env.database.remove(old_name);
                env.database.set(new_name, &hashword);
                env.user = new_name.clone();
                0
            } else {
                println!("failed authentication");
                1
            }
        }
    }
}

static CHNAME: Command = Command {
    name: "chname",
    usage: "chname [old] <new>",
    description: "change account username",
    permissions: P_USER,
    handler: f_chname,
};

// ==== CHPASS ====
#[allow(unused_variables)]
fn f_chpass(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    if argc == 1 {
        if authenticate(
            &env.database,
            &env.user,
            &password_input("current password: ", false),
        ) {
            env.database.set(
                &env.user,
                &hash_password(
                    &password_input("new password: ", true),
                    &get_salt(None),
                    DEF_HASH_COST,
                ),
            );
            println!("changed password for {}", env.user);
            0
        } else {
            println!("failed to authenticate");
            1
        }
    } else if argc == 2 && env.permissions >= P_ROOT {
        if authenticate(
            &env.database,
            ROOT,
            &password_input("root password: ", false),
        ) {
            let target_user = &argv[1];
            if !env.database.contains(&target_user) {
                println!("account {} not found", target_user);
                return 1;
            }
            env.database.set(
                target_user,
                &hash_password(
                    &password_input("new account password: ", true),
                    &get_salt(None),
                    DEF_HASH_COST,
                ),
            );
            println!("changed {}'s password", target_user);
            0
        } else {
            println!("failed to authenticate as root");
            1
        }
    } else {
        println!("invalid arguments for {}", argv[0]);
        1
    }
}

static CHPASS: Command = Command {
    name: "chpass",
    usage: "chpass <username>",
    description: "change account password",
    permissions: P_USER,
    handler: f_chpass,
};

// ==== SWITCHUSER ====
#[allow(unused_variables)]
fn f_switchuser(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    if env.user == NULLUSER {
        println!("not logged in");
        return 1;
    }
    if argc != 2 {
        println!("invalid arguments for {}.", argv[0]);
        return 1;
    }
    if authenticate(
        &env.database,
        &argv[1],
        &password_input("Password: ", false),
    ) {
        env.user = argv[1].clone();
        if env.user == ROOT {
            env.permissions = P_ROOT;
        } else {
            env.permissions = P_USER;
        }
        println!("logged in as {}.", env.user);
        return 0;
    } else {
        println!("failed to authenticate as {}", argv[1]);
    }
    1
}

static SWITCHUSER: Command = Command {
    name: "switchuser",
    usage: "switchuser <username>",
    description: "logout and login as another user",
    permissions: P_USER,
    handler: f_switchuser,
};

// ==== LOGOUT ====
#[allow(unused_variables)]
fn f_logout(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    println!("logged out of {}", env.user);
    env.user = NULLUSER.to_string();
    env.permissions = P_NONE;
    0
}

static LOGOUT: Command = Command {
    name: "logout",
    usage: "logout",
    description: "logout of account",
    permissions: P_USER,
    handler: f_logout,
};

// ==== LOGIN ====
#[allow(unused_variables)]
fn f_login(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    if env.user != NULLUSER {
        println!("already logged in: {}", env.user);
        return 1;
    }

    if argc != 2 {
        println!("invalid arguments for {}.", argv[0]);
        return 1;
    }

    if authenticate(
        &env.database,
        &argv[1],
        &password_input("Password: ", false),
    ) {
        env.user = argv[1].clone();
        if env.user == ROOT {
            env.permissions = P_ROOT;
        } else {
            env.permissions = P_USER;
        }
        println!("logged in as {}", argv[1]);
        return 0;
    } else {
        println!("failed to authenticate as {}", argv[1]);
    }
    1
}

static LOGIN: Command = Command {
    name: "login",
    usage: "login <username>",
    description: "login to an account",
    permissions: P_NONE,
    handler: f_login,
};

// ==== RMUSER ====
#[allow(unused_variables)]
fn f_rmuser(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    if argc != 2 {
        println!("invalid arguments for {}", argv[1]);
        1
    } else {
        if authenticate(
            &env.database,
            &ROOT,
            &password_input("root password: ", false),
        ) {
            if argv[1] == ROOT {
                println!("cannot delete root account");
                1
            } else {
                env.database.remove(&argv[1]);
                println!("deleted account {}", argv[1]);
                0
            }
        } else {
            println!("failed to authenticate as root");
            1
        }
    }
}

static RMUSER: Command = Command {
    name: "rmuser",
    usage: "rmuser <username>",
    description: "delete an account",
    permissions: P_ROOT,
    handler: f_rmuser,
};

// ==== RESET ====
#[allow(unused_variables)]
fn f_reset(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    if argc != 1 {
        println!("invalide arguments for {}", argv[0]);
        1
    } else {
        if authenticate(
            &env.database,
            ROOT,
            &password_input("root password: ", false),
        ) {
            if inline_input("Are you sure you wish to delete all user information? [Y/n]: ")
                .to_lowercase()
                == "y"
            {
                for username in env.database.list_users() {
                    env.database.remove(&username);
                }
                env.user = NULLUSER.to_string();
                env.permissions = P_NONE;
                println!("all accouns deleted");
                0
            } else {
                0
            }
        } else {
            println!("failed to authenticate as root");
            1
        }
    }
}

static RESET: Command = Command {
    name: "reset",
    usage: "reset",
    description: "delete all accounts",
    permissions: P_ROOT,
    handler: f_reset,
};

// ==== EXIT ====
#[allow(unused_variables)]
fn f_exit(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    1
}

static EXIT: Command = Command {
    name: "exit",
    usage: "exit",
    description: "exit shell",
    permissions: P_NONE,
    handler: f_exit,
};

// ==================== MAINLOOP ====================

/// This is a pseudo-shell to simulate logins and credential management
#[allow(unused_variables)]
fn main() {
    println!("=== UN*X USER MANAGEMENT ===");

    let mut env: Environment = Environment {
        user: NULLUSER.to_string(),
        permissions: P_NONE,
        database: UserCredentials::new(STORAGE_PATH.to_string()),
        commands: vec![
            &HELP,
            &WHOAMI,
            &USERS,
            &CLEAR,
            &LOGOUT,
            &LOGIN,
            &SWITCHUSER,
            &CHNAME,
            &CHPASS,
            &RMUSER,
            &MKUSER,
            &RESET,
            &EXIT,
        ],
    };

    loop {
        if !env.database.contains(ROOT) {
            println!("no root account found, creating one.");
            env.database.set(
                &ROOT,
                &&hash_password(
                    &password_input("root password: ", true),
                    &get_salt(None),
                    DEF_HASH_COST,
                ),
            );
            println!("root created");
        }

        let prompt = match env.user.as_str() {
            NULLUSER => "$ ".to_string(),
            _ => format!("{} $ ", &env.user),
        };

        // let argv: Vec<String> = inline_input(&prompt).split(' ').map(String::from).collect();
        let argv: Vec<String> = inline_input(&prompt)
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let argc: u8 = argv.len() as u8;

        if argc == 0 {
            continue;
        }

        if argv[0] == "exit" {
            break;
        }

        if let Some(cmd) = env.commands.iter().copied().find(|c| c.name == argv[0]) {
            if env.permissions < cmd.permissions {
                println!("permission denied: {}.", cmd.name);
                continue;
            }

            let ret_code = (cmd.handler)(&mut env, argc, &argv);
        } else {
            println!("unknown command: {}. try 'help'.", argv[0])
        }
    }
}
