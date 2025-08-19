// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{
        Algorithms, Cli, Commands, Convert, CreatePrimary, Delete, Import, Load, Objects, PcrEvent,
        PcrRead, Policy, PrintError, PrintStack, ResetLock, Save, Seal, StartSession, Unseal,
    },
    Command, TpmError,
};
use std::{ffi::OsString, fmt::Write};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type CommandLineOption<'a> = (Option<&'a str>, &'a str, &'a str, &'a str);
pub type CommandLineArgument<'a> = (&'a str, &'a str);

fn format_help_section(title: &str, items: &[(String, &str)], max_len: usize) -> String {
    let mut output = format!("\n{title}:\n");
    for (left, right) in items {
        let _ = writeln!(output, "    {left:<max_len$}  {right}");
    }
    output
}

#[must_use]
pub fn format_subcommand_help(
    name: &str,
    about: &str,
    usage: &str,
    args: &[CommandLineArgument],
    options: &[CommandLineOption],
) -> String {
    let mut output = format!("tpm2sh-{name}\n{about}\n\nUSAGE:\n    {usage}");

    let arg_items: Vec<(String, &str)> = args
        .iter()
        .map(|(name, desc)| ((*name).to_string(), *desc))
        .collect();

    let opt_items: Vec<(String, &str)> = options
        .iter()
        .map(|(short, long, val, desc)| {
            let mut left = if let Some(s) = short {
                format!("{s}, ")
            } else {
                "    ".to_string()
            };
            left.push_str(long);
            if !val.is_empty() {
                left.push(' ');
                left.push_str(val);
            }
            (left, *desc)
        })
        .collect();

    let max_len = arg_items
        .iter()
        .chain(opt_items.iter())
        .map(|(left, _)| left.len())
        .max()
        .unwrap_or(0);

    if !args.is_empty() {
        output.push_str(&format_help_section("ARGS", &arg_items, max_len));
    }
    if !options.is_empty() {
        output.push_str(&format_help_section("OPTIONS", &opt_items, max_len));
    }

    output
}

struct Subcommand {
    name: &'static str,
    about: &'static str,
}

const SUBCOMMANDS: &[Subcommand] = &[
    Subcommand {
        name: "algorithms",
        about: "Lists available algorithms",
    },
    Subcommand {
        name: "convert",
        about: "Converts keys between ASN.1 and JSON format",
    },
    Subcommand {
        name: "create-primary",
        about: "Creates a primary key",
    },
    Subcommand {
        name: "delete",
        about: "Deletes a transient or persistent object",
    },
    Subcommand {
        name: "import",
        about: "Imports an external key",
    },
    Subcommand {
        name: "load",
        about: "Loads a TPM key",
    },
    Subcommand {
        name: "objects",
        about: "Lists objects in volatile and non-volatile memory",
    },
    Subcommand {
        name: "pcr-event",
        about: "Extends a PCR with an event",
    },
    Subcommand {
        name: "pcr-read",
        about: "Reads PCRs",
    },
    Subcommand {
        name: "policy",
        about: "Builds a policy using a policy expression",
    },
    Subcommand {
        name: "print-error",
        about: "Encodes and print a TPM error code",
    },
    Subcommand {
        name: "print-stack",
        about: "Prints a human-readable summary of the object stack to stderr",
    },
    Subcommand {
        name: "reset-lock",
        about: "Resets the dictionary attack lockout timer",
    },
    Subcommand {
        name: "save",
        about: "Saves to non-volatile memory",
    },
    Subcommand {
        name: "seal",
        about: "Seals a keyedhash object",
    },
    Subcommand {
        name: "start-session",
        about: "Starts an authorization session",
    },
    Subcommand {
        name: "unseal",
        about: "Unseals a keyedhash object",
    },
];

const GLOBAL_OPTIONS: &[CommandLineOption] = &[
    (Some("-d"), "--device", "<DEVICE>", "[default: /dev/tpmrm0]"),
    (
        None,
        "--log-format",
        "<FORMAT>",
        "[default: plain, possible: plain, pretty]",
    ),
    (Some("-h"), "--help", "", "Print help information"),
    (Some("-V"), "--version", "", "Print version information"),
];

fn print_usage() {
    let mut output =
        format!("tpm2sh {VERSION}\nTPM 2.0 shell\n\nUSAGE:\n    tpm2sh [OPTIONS] <COMMAND>");

    let opt_items: Vec<(String, &str)> = GLOBAL_OPTIONS
        .iter()
        .map(|(short, long, val, desc)| {
            let mut left = if let Some(s) = short {
                format!("{s}, ")
            } else {
                "    ".to_string()
            };
            left.push_str(long);
            if !val.is_empty() {
                left.push(' ');
                left.push_str(val);
            }
            (left, *desc)
        })
        .collect();

    let max_len = opt_items
        .iter()
        .map(|(left, _)| left.len())
        .max()
        .unwrap_or(0);
    output.push_str(&format_help_section("OPTIONS", &opt_items, max_len));
    println!("{output}");
}

fn print_main_help() {
    print_usage();
    let mut output = "\nSUBCOMMANDS:\n".to_string();
    for cmd in SUBCOMMANDS {
        let _ = writeln!(output, "    {: <20} {}", cmd.name, cmd.about);
    }
    println!("{output}");
}

fn print_version() {
    println!("tpm2sh {VERSION}");
}

/// Dispatch parsing to the correct subcommand implementation.
fn dispatch_subcommand(
    cmd_name: &OsString,
    parser: &mut lexopt::Parser,
) -> Result<Commands, TpmError> {
    match cmd_name.to_str() {
        Some("algorithms") => Algorithms::parse(parser),
        Some("convert") => Convert::parse(parser),
        Some("create-primary") => CreatePrimary::parse(parser),
        Some("delete") => Delete::parse(parser),
        Some("import") => Import::parse(parser),
        Some("load") => Load::parse(parser),
        Some("objects") => Objects::parse(parser),
        Some("pcr-event") => PcrEvent::parse(parser),
        Some("pcr-read") => PcrRead::parse(parser),
        Some("policy") => Policy::parse(parser),
        Some("print-error") => PrintError::parse(parser),
        Some("print-stack") => PrintStack::parse(parser),
        Some("reset-lock") => ResetLock::parse(parser),
        Some("save") => Save::parse(parser),
        Some("seal") => Seal::parse(parser),
        Some("start-session") => StartSession::parse(parser),
        Some("unseal") => Unseal::parse(parser),
        Some(cmd) => Err(TpmError::Usage(format!("unknown command '{cmd}'"))),
        None => Err(TpmError::Usage("invalid non-UTF8 command".to_string())),
    }
}

/// Parse command-line arguments.
///
/// # Errors
///
/// Returns a `TpmError::Execute` on a failure.
pub fn parse_cli() -> Result<Option<Cli>, TpmError> {
    use lexopt::prelude::*;

    let mut cli = Cli {
        device: "/dev/tpmrm0".to_string(),
        ..Default::default()
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                print_main_help();
                return Ok(None);
            }
            Short('V') | Long("version") => {
                print_version();
                return Ok(None);
            }
            Short('d') | Long("device") => {
                cli.device = parser.value()?.string()?;
            }
            Long("log-format") => {
                cli.log_format = parser.value()?.string()?.parse()?;
            }
            Value(val) => {
                cli.command = Some(dispatch_subcommand(&val, &mut parser)?);
                break;
            }
            _ => return Err(TpmError::from(arg.unexpected())),
        }
    }

    if cli.command.is_none() {
        print_usage();
        return Err(TpmError::HelpDisplayed);
    }

    Ok(Some(cli))
}
