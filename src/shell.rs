// ==================== IMPORTS ====================

use crate::auth_utils::*;

// ==================== CONSTANTS ====================

/// predefined nulluser name
pub const NULLUSER: &str = "";

/// predefined root user name
pub const ROOT: &str = "root";

/// Permission levels
pub const P_NONE: u8 = 0;
pub const P_USER: u8 = 1;
// pub const P_SUDO: u8 = 2;
pub const P_ROOT: u8 = 3;

// ==================== STRUCTURES ====================

/// structure to hold information about shell a command
/// # Fields
/// * name - name as called from the shell
/// * usage - for help messsage, command args/flags
/// * description - for help message, describes functionality
/// * permissions - permissions level, i.e. who can run command
/// * handler - function handler that actually does the command
pub struct Command {
    pub name: &'static str,
    pub usage: &'static str,
    pub description: &'static str,
    pub permissions: u8,
    pub handler: fn(&mut Environment, u8, &[String]) -> i8,
}

/// structure for environment variables
/// Fields
/// * user - username of active user
/// * permissions - permissions level of active user
/// * commands - vector of registered shell commands
/// * database - struct managing credentials
pub struct Environment {
    pub user: String,
    pub permissions: u8,
    pub commands: Vec<&'static Command>,
    pub database: UserCredentials,
}

// ==================== COMMANDS ====================

// ==== HELP ====
#[allow(unused_variables)]
fn f_help(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    // get commands as vec
    let cmds: Vec<&Command> = env
        .commands
        .iter()
        .copied()
        .filter(|c| env.permissions >= c.permissions)
        .collect();

    // filter commands by permissions
    let mut max_usage_size: usize = 0;
    for cmd in &cmds {
        if cmd.usage.len() > max_usage_size {
            max_usage_size = cmd.usage.len();
        }
    }

    // print commands
    println!("available commands:");
    for cmd in &cmds {
        println!("{:<max_usage_size$}  {}", cmd.usage, cmd.description);
    }
    0
}

pub static HELP: Command = Command {
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

pub static WHOAMI: Command = Command {
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
        // prevent collisions
        if env.database.contains(&argv[1]) {
            println!("account {} already exists", argv[1]);
            1
        } else {
            // create user
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

pub static MKUSER: Command = Command {
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

pub static USERS: Command = Command {
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

pub static CLEAR: Command = Command {
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
        // root path: change another account name
        if argc != 3 {
            println!("invalid arguments for {} as root", argv[0]);
            1
        } else {
            if env
                .database
                .authenticate(ROOT, &password_input("root password: ", false))
            {
                let old_name = &argv[1];
                let new_name = &argv[2];
                // ensure account
                if env.database.contains(new_name) {
                    println!("account {} already exists", new_name);
                    return 1;
                }
                // prevent collisions
                if !env.database.contains(old_name) {
                    println!("account {} not found", old_name);
                    return 1;
                }
                // fetch credential string
                let hashword = env
                    .database
                    .get(old_name)
                    .expect("failed to retrieve hashed password")
                    .clone();
                // change account
                env.database.remove(old_name);
                env.database.set(new_name, &hashword);
                0
            } else {
                println!("could not authenticate as root");
                1
            }
        }
    } else {
        // user path: change own account name
        if argc != 2 {
            println!("invalid arguments for {}", argv[0]);
            1
        } else {
            if env
                .database
                .authenticate(&env.user, &password_input("password: ", false))
            {
                let old_name = &env.user;
                let new_name = &argv[1];
                // prevent collisions
                if env.database.contains(new_name) {
                    println!("account {} already exists", new_name);
                    return 1;
                }
                // change account name
                let hashword = env
                    .database
                    .get(old_name)
                    .expect("failed to reitreive hashed password")
                    .clone();
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

pub static CHNAME: Command = Command {
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
        // change own password
        if env
            .database
            .authenticate(&env.user, &password_input("current password: ", false))
        {
            // change to new password
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
        // root path: change other account password
        if env
            .database
            .authenticate(ROOT, &password_input("root password: ", false))
        {
            // ensure account exists
            let target_user = &argv[1];
            if !env.database.contains(&target_user) {
                println!("account {} not found", target_user);
                return 1;
            }
            // change password
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

pub static CHPASS: Command = Command {
    name: "chpass",
    usage: "chpass [username]",
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
        println!("invalid arguments for {}", argv[0]);
        return 1;
    }
    if env
        .database
        .authenticate(&argv[1], &password_input("Password: ", false))
    {
        env.user = argv[1].clone();
        if env.user == ROOT {
            env.permissions = P_ROOT;
        } else {
            env.permissions = P_USER;
        }
        println!("logged in as {}", env.user);
        return 0;
    } else {
        println!("failed to authenticate as {}", argv[1]);
    }
    1
}

pub static SWITCHUSER: Command = Command {
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

pub static LOGOUT: Command = Command {
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
        println!("invalid arguments for {}", argv[0]);
        return 1;
    }

    if env
        .database
        .authenticate(&argv[1], &password_input("Password: ", false))
    {
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

pub static LOGIN: Command = Command {
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
        if env
            .database
            .authenticate(&ROOT, &password_input("root password: ", false))
        {
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

pub static RMUSER: Command = Command {
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
        println!("this action will destroy all accounts.");
        if env
            .database
            .authenticate(ROOT, &password_input("enter password to proceed: ", false))
        {
            print!("\x1bc"); // ANSI escape code to clear terminal screen
            for username in env.database.list_users() {
                env.database.remove(&username);
            }
            env.user = NULLUSER.to_string();
            env.permissions = P_NONE;
            println!("all accounts deleted\n");
            0
        } else {
            println!("failed to authenticate as root");
            1
        }
    }
}

pub static RESET: Command = Command {
    name: "reset",
    usage: "reset",
    description: "delete all accounts",
    permissions: P_ROOT,
    handler: f_reset,
};

// ==== EXIT ====
#[allow(unused_variables)]
fn f_exit(env: &mut Environment, argc: u8, argv: &[String]) -> i8 {
    1 // blank function for exit entry
}

pub static EXIT: Command = Command {
    name: "exit",
    usage: "exit",
    description: "exit shell",
    permissions: P_NONE,
    handler: f_exit,
};
