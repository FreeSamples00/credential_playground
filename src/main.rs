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

/// prompt icon
const PROMPT_ICON: &str = "$ ";

/// toggle color mode
const COLOR_MODE: bool = true;

/// prompt username color
const USERNAME_COLOR: &str = "92";

/// prompt root username colo
const USERNAME_ROOT_COLOR: &str = "91";

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

/// This is the REPL to simulate logins and credential management
#[allow(unused_variables)]
fn main() {
    println!("\n=== Credential Playground ===");

    // setup environment variables
    let mut env: Environment = Environment {
        user: NULLUSER.to_string(),                   // start out logged out
        permissions: P_NONE,                          // start out logged oud
        database: UserCredentials::new(STORAGE_PATH), // load passwd file
        // reference all commands
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

    // REPL mainloop
    loop {
        // create root user if none found
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

        // generate prompt string
        let (p_username, p_icon) = match env.user.as_str() {
            NULLUSER => ("".to_string(), PROMPT_ICON.to_string()),
            _ => (format!("{} ", env.user), PROMPT_ICON.to_string()),
        };

        // determine color
        let prompt_color = match env.user.as_str() {
            ROOT => USERNAME_ROOT_COLOR,
            _ => USERNAME_COLOR,
        };

        // possibly apply color
        let prompt = match COLOR_MODE {
            true => format!("\x1b[{}m{}\x1b[0m{}", prompt_color, p_username, p_icon),
            false => format!("{}{}", p_username, p_icon),
        };

        // take commandline input and create argv list
        let argv: Vec<String> = inline_input(&prompt)
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let argc: u8 = argv.len() as u8;

        // create argc count
        if argc == 0 {
            continue;
        }

        // harcoded exit command
        if argv[0] == "exit" {
            break;
        }

        // search commandlist
        if let Some(cmd) = env.commands.iter().copied().find(|c| c.name == argv[0]) {
            // check permissions for command
            if env.permissions < cmd.permissions {
                println!("permission denied: {}", cmd.name);
                continue;
            }

            // run command w/ args
            let ret_code = (cmd.handler)(&mut env, argc, &argv);
        } else {
            println!("unknown command: {}. try 'help'", argv[0])
        }
    }
}
