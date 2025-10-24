# Credential Playground

## Introduction

This project consists of a unix-style faux shell where you can do various account operations in fake environment, and a utility library for hashing, storing, and authenticating passwords.

Passwords are stored in a linux-style `passwd` file and are hashed with iterative sha-256. I implemented the sha-256 algorithm myself; it matches the standard as far as I can tell, but I **would not** trust it with anything important.

## Faux-shell

### Commands

|   Command    |     Arguments      | Min Privilege | Description                                              |
| :----------: | :----------------: | :-----------: | -------------------------------------------------------- |
|   `users`    |                    |     None      | list all accounts                                        |
|    `help`    |                    |     None      | list all commands                                        |
|   `whoami`   |                    |     None      | print current username                                   |
|   `clear`    |                    |     None      | clear screen                                             |
|    `exit`    |                    |     None      | exit the shell                                           |
|   `login`    |    `<account>`     |     None      | login to an account                                      |
|   `logout`   |                    |     User      | logout of an account                                     |
| `switchuser` |    `<account>`     |     User      | logout and login to another account                      |
|   `chname`   | `[account] <name>` |     User      | change account name, if root change a different accounts |
|   `chpass`   |    `[account]`     |     User      | change password, if root can change another account      |
|   `mkuser`   |    `<account>`     |     Root      | create an account                                        |
|   `rmuser`   |    `<account>`     |     Root      | delete an account                                        |
|   `reset`    |                    |     Root      | delete all accounts, logout                              |

### Implementation

The state of the shell is managed via an `Environment` structure. This structure manages logged in users and permissions, as well as holding the command list (`path` in real systems) and the credential database.

```rust
pub struct Environment {
    pub user: String, // current user
    pub permissions: u8, // current permissions level
    pub commands: Vec<&'static Command>, // shell commands
    pub database: UserCredentials, // credential database
}
```

Commands are implemented in functions in the `shell.rs` file, and they are tracked by the environment with the `Command` structure.

```rust
pub struct Command {
    pub name: &'static str, // how command is called
    pub usage: &'static str, // usage for help message
    pub description: &'static str, // description for help message
    pub permissions: u8, // minimum permissions required to run
    pub handler: fn(&mut Environment, u8, &[String]) -> i8, // reference to handler function
}
```
