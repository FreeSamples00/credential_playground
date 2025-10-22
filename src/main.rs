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

#[derive(Debug)]
struct Command {
    name: &'static str,
    usage: &'static str,
    description: &'static str,
    permissions: u8,
    handler: fn(u8, &[String]) -> i8,
}

#[derive(Debug)]
struct Environment {
    user: String,
    permissions: u8,
    commands: Vec<&'static Command>,
    database: UserCredentials,
}

// ==================== COMMANDS ====================

// ==== HELP ====
fn f_help(argc: u8, argv: &[String]) -> i8 {
    todo!();
}

static HELP: Command = Command {
    name: "help",
    usage: "help",
    description: "display this helpful message",
    permissions: P_NONE,
    handler: f_help,
};

// ==== WHOAMI ====
fn f_whoami(argc: u8, argv: &[String]) -> i8 {
    todo!();
}

static WHOAMI: Command = Command {
    name: "whoami",
    usage: "whoami",
    description: "print username",
    permissions: P_NONE,
    handler: f_whoami,
};

// ==== MAKEUSER ====
fn f_mkuser(argc: u8, argv: &[String]) -> i8 {
    todo!();
}

static MKUSER: Command = Command {
    name: "mkuser",
    usage: "mkuser <username>",
    description: "create a user account",
    permissions: P_ROOT,
    handler: f_mkuser,
};

// ==== USERS ====
fn f_users(argc: u8, argv: &[String]) -> i8 {
    todo!();
}

static USERS: Command = Command {
    name: "users",
    usage: "users",
    description: "list all users",
    permissions: P_NONE,
    handler: f_users,
};

// ==== CLEAR ====
fn f_clear(argc: u8, argv: &[String]) -> i8 {
    todo!();
}

static CLEAR: Command = Command {
    name: "clear",
    usage: "clear",
    description: "clear the screen",
    permissions: P_NONE,
    handler: f_clear,
};

// ==== CHNAME ====
fn f_chname(argc: u8, argv: &[String]) -> i8 {
    todo!();
    // TODO:
    // if perms >= sudo -> allow for changing another name
    // else -> change self name (w/ pass)
}

static CHNAME: Command = Command {
    name: "chname",
    usage: "chname [old] <new>",
    description: "change account username",
    permissions: P_USER,
    handler: f_chname,
};

// ==== CHPASS ====
fn f_chpass(argc: u8, argv: &[String]) -> i8 {
    todo!();
    // TODO:
    // if root -> can change another account
    // else -> own account
}

static CHPASS: Command = Command {
    name: "chpass",
    usage: "chpass <username>",
    description: "change account password",
    permissions: P_USER,
    handler: f_chpass,
};

// ==== SWITCHUSER ====
fn f_switchuser(argc: u8, argv: &[String]) -> i8 {
    todo!();
}

static SWITCHUSER: Command = Command {
    name: "switchuser",
    usage: "switchuser <username>",
    description: "logout and login as another user",
    permissions: P_USER,
    handler: f_switchuser,
};

// ==== LOGOUT ====
fn f_logout(argc: u8, argv: &[String]) -> i8 {
    todo!();
}

static LOGOUT: Command = Command {
    name: "logout",
    usage: "logout",
    description: "logout of account",
    permissions: P_USER,
    handler: f_logout,
};

// ==== LOGIN ====
fn f_login(argc: u8, argv: &[String]) -> i8 {
    todo!();
    // TODO: err if logged in
}

static LOGIN: Command = Command {
    name: "login",
    usage: "login <username>",
    description: "login to an account",
    permissions: P_NONE,
    handler: f_login,
};

// ==== RMUSER ====
fn f_rmuser(argc: u8, argv: &[String]) -> i8 {
    todo!();
    // TODO: password confirm
}

static RMUSER: Command = Command {
    name: "rmuser",
    usage: "rmuser <username>",
    description: "delete an account",
    permissions: P_ROOT,
    handler: f_rmuser,
};

// ==== RESET ====
fn f_reset(argc: u8, argv: &[String]) -> i8 {
    todo!();
    // TODO: password confirm
}

static RESET: Command = Command {
    name: "reset",
    usage: "reset",
    description: "delete all accounts",
    permissions: P_ROOT,
    handler: f_reset,
};

// ==================== MAINLOOP ====================

/// This is a pseudo-shell to simulate logins and credential management
fn main() {
    println!("=== UN*X USER MANAGEMENT ===");

    let mut env: Environment = Environment {
        user: NULLUSER.to_string(),
        permissions: P_NONE,
        database: UserCredentials::new(STORAGE_PATH.to_string()),
        commands: vec![&HELP, &WHOAMI, &MKUSER],
    };

    loop {
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

        if let Some(cmd) = env.commands.iter().copied().find(|c| c.name == argv[0]) {
            if env.permissions < cmd.permissions {
                eprintln!("permission denied: {}.", cmd.name);
                continue;
            }

            let ret_code = (cmd.handler)(argc, &argv);
        } else {
            eprintln!("unknown command: {}. Try 'help'.", argv[0])
        }
    }
}
