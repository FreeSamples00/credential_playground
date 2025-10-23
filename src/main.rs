// src/main.rs

// ==================== IMPORTS ====================

mod auth_utils;
use auth_utils::*;

mod shell;
use shell::*;

use std::io::{self, Write};

// ==================== CONSTANTS ====================

/// path to file where user data is stored
const STORAGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/passwd");

// ==================== HELPERS ====================

/// function to get inline input from the user
/// # Arguments
/// * `prompt` - &str with which to prompt the user for input
/// # Return
/// * input given by the user
pub fn inline_input(prompt: &str) -> String {
    let mut input_buffer: String = String::new();
    print!("{}", prompt);
    io::stdout().flush().expect("stdout.flush() failed");
    io::stdin()
        .read_line(&mut input_buffer)
        .expect("stdin.read_line() failed");
    input_buffer.trim().into()
}

// ==================== MAINLOOP ====================

/// This is a pseudo-shell to simulate logins and credential management
#[allow(unused_variables)]
fn main() {
    println!("\n=== Credential Playground ===");

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
            println!("no root account found, creating one");
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
                println!("permission denied: {}", cmd.name);
                continue;
            }

            let ret_code = (cmd.handler)(&mut env, argc, &argv);
        } else {
            println!("unknown command: {}. try 'help'", argv[0])
        }
    }
}
