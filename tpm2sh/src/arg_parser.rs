// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{
        Algorithms, Cli, Commands, Convert, CreatePrimary, Delete, Import, Load, Objects, PcrEvent,
        PcrRead, Policy, PrintError, ResetLock, Save, Seal, StartSession, Unseal,
    },
    parse_hex_u32, parse_persistent_handle, parse_tpm_rc, TpmError,
};
use std::{env::Args, fmt::Write};

const VERSION: &str = env!("CARGO_PKG_VERSION");

type CommandLineOption<'a> = (Option<&'a str>, &'a str, &'a str, &'a str);
type CommandLineArgument<'a> = (&'a str, &'a str);

const GLOBAL_OPTIONS: &[CommandLineOption] = &[
    (Some("-d"), "--device", "<DEVICE>", "[default: /dev/tpmrm0]"),
    (
        None,
        "--log-format",
        "<FORMAT>",
        "[default: plain, possible: plain, pretty]",
    ),
    (
        None,
        "--session",
        "<SESSION>",
        "Authorization session context",
    ),
    (Some("-h"), "--help", "", "Print help information"),
    (Some("-V"), "--version", "", "Print version information"),
];

const ALGORITHMS_ABOUT: &str = "Lists available algorithms";
const CONVERT_ABOUT: &str = "Converts keys between ASN.1 and JSON format";
const CREATE_PRIMARY_ABOUT: &str = "Creates a primary key";
const DELETE_ABOUT: &str = "Deletes a transient or persistent object";
const IMPORT_ABOUT: &str = "Imports an external key";
const LOAD_ABOUT: &str = "Loads a TPM key";
const OBJECTS_ABOUT: &str = "Lists objects in volatile and non-volatile memory";
const PCR_EVENT_ABOUT: &str = "Extends a PCR with an event";
const PCR_READ_ABOUT: &str = "Reads PCRs";
const POLICY_ABOUT: &str = "Builds a policy using a policy expression";
const PRINT_ERROR_ABOUT: &str = "Encodes and print a TPM error code";
const RESET_LOCK_ABOUT: &str = "Resets the dictionary attack lockout timer";
const SAVE_ABOUT: &str = "Saves to non-volatile memory";
const SEAL_ABOUT: &str = "Seals a keyedhash object";
const START_SESSION_ABOUT: &str = "Starts an authorization session";
const UNSEAL_ABOUT: &str = "Unseals a keyedhash object";

const ALGORITHMS_USAGE: &str = "tpm2sh algorithms [OPTIONS]";
const ALGORITHMS_OPTIONS: &[CommandLineOption] = &[(
    None,
    "--filter",
    "<REGEX>",
    "A regex to filter the algorithm names",
)];

const CONVERT_USAGE: &str = "tpm2sh convert [OPTIONS]";
const CONVERT_OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--from",
        "<FORMAT>",
        "Input format [default: json, possible: json, pem, der]",
    ),
    (
        None,
        "--to",
        "<FORMAT>",
        "Output format [default: pem, possible: json, pem, der]",
    ),
];

const CREATE_PRIMARY_USAGE: &str = "tpm2sh create-primary [OPTIONS] --alg <ALG>";
const CREATE_PRIMARY_OPTIONS: &[CommandLineOption] = &[
    (
        Some("-H"),
        "--hierarchy",
        "<HIERARCHY>",
        "[default: owner, possible: owner, platform, endorsement]",
    ),
    (
        None,
        "--alg",
        "<ALGORITHM>",
        "Public key algorithm. Run 'algorithms' for options",
    ),
    (
        None,
        "--persistent",
        "<HANDLE>",
        "Store object to non-volatile memory",
    ),
    (
        None,
        "--auth",
        "<AUTH>",
        "Authorization value for the hierarchy",
    ),
];

const DELETE_USAGE: &str = "tpm2sh delete [OPTIONS] <HANDLE>";
const DELETE_ARGS: &[CommandLineArgument] = &[("<HANDLE>", "Handle of the object to delete")];
const DELETE_OPTIONS: &[CommandLineOption] = &[(None, "--auth", "<AUTH>", "Authorization value")];

const IMPORT_USAGE: &str = "tpm2sh import [OPTIONS]";
const IMPORT_OPTIONS: &[CommandLineOption] = &[(
    None,
    "--auth",
    "<AUTH>",
    "Authorization for the parent object",
)];

const LOAD_USAGE: &str = "tpm2sh load [OPTIONS]";
const LOAD_OPTIONS: &[CommandLineOption] = &[(
    None,
    "--auth",
    "<AUTH>",
    "Authorization for the parent object",
)];

const OBJECTS_USAGE: &str = "tpm2sh objects";

const PCR_EVENT_USAGE: &str = "tpm2sh pcr-event [OPTIONS] <DATA>";
const PCR_EVENT_ARGS: &[CommandLineArgument] = &[("<DATA>", "Data to be hashed and extended")];
const PCR_EVENT_OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--pcr-handle",
        "<HANDLE>",
        "Handle of the PCR to extend",
    ),
    (None, "--auth", "<AUTH>", "Authorization value"),
];

const PCR_READ_USAGE: &str = "tpm2sh pcr-read <SELECTION>";
const PCR_READ_ARGS: &[CommandLineArgument] = &[("<SELECTION>", "e.g. 'sha256:0,1,2+sha1:0'")];

const POLICY_USAGE: &str = "tpm2sh policy [OPTIONS] <EXPRESSION>";
const POLICY_ARGS: &[CommandLineArgument] = &[("<EXPRESSION>", "e.g. 'pcr(\"sha256:0\",\"...\"')")];
const POLICY_OPTIONS: &[CommandLineOption] = &[
    (None, "--auth", "<AUTH>", "Authorization value"),
    (
        Some("-p"),
        "--partial",
        "",
        "Enable partial consumption of the PCR object",
    ),
];

const PRINT_ERROR_USAGE: &str = "tpm2sh print-error <RC>";
const PRINT_ERROR_ARGS: &[CommandLineArgument] = &[("<RC>", "TPM error code")];

const RESET_LOCK_USAGE: &str = "tpm2sh reset-lock [OPTIONS]";
const RESET_LOCK_OPTIONS: &[CommandLineOption] =
    &[(None, "--auth", "<AUTH>", "Authorization value")];

const SAVE_USAGE: &str = "tpm2sh save [OPTIONS]";
const SAVE_OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--object-handle",
        "<HANDLE>",
        "Handle of the transient object",
    ),
    (
        None,
        "--persistent-handle",
        "<HANDLE>",
        "Handle for the persistent object to be created",
    ),
    (None, "--auth", "<AUTH>", "Authorization value"),
];

const SEAL_USAGE: &str = "tpm2sh seal [OPTIONS]";
const SEAL_OPTIONS: &[CommandLineOption] = &[(
    None,
    "--auth",
    "<AUTH>",
    "Authorization value (use once for parent, twice for object)",
)];

const START_SESSION_USAGE: &str = "tpm2sh start-session [OPTIONS]";
const START_SESSION_OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--session-type",
        "<TYPE>",
        "[default: hmac, possible: hmac, policy, trial]",
    ),
    (
        None,
        "--hash-alg",
        "<ALG>",
        "[default: sha256, possible: sha256, sha384, sha512]",
    ),
];

const UNSEAL_USAGE: &str = "tpm2sh unseal [OPTIONS]";
const UNSEAL_OPTIONS: &[CommandLineOption] = &[(None, "--auth", "<AUTH>", "Authorization value")];

fn format_help_section(title: &str, items: &[(String, &str)], max_len: usize) -> String {
    let mut output = format!("\n{title}:\n");
    for (left, right) in items {
        let _ = writeln!(output, "    {left:<max_len$}    {right}");
    }
    output
}

fn format_subcommand_help(
    name: &str,
    about: &str,
    usage: &str,
    args: &[CommandLineArgument],
    options: &[CommandLineOption],
) -> String {
    let mut output = format!("tpm2sh-{name}\n{about}\n\nUSAGE:\n    {usage}");

    let all_options: Vec<CommandLineOption> =
        [(Some("-h"), "--help", "", "Print help information")]
            .iter()
            .chain(options.iter())
            .copied()
            .collect();

    let arg_items: Vec<(String, &str)> = args
        .iter()
        .map(|(name, desc)| ((*name).to_string(), *desc))
        .collect();
    let opt_items: Vec<(String, &str)> = all_options
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
    if !all_options.is_empty() {
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
        about: ALGORITHMS_ABOUT,
    },
    Subcommand {
        name: "convert",
        about: CONVERT_ABOUT,
    },
    Subcommand {
        name: "create-primary",
        about: CREATE_PRIMARY_ABOUT,
    },
    Subcommand {
        name: "delete",
        about: DELETE_ABOUT,
    },
    Subcommand {
        name: "import",
        about: IMPORT_ABOUT,
    },
    Subcommand {
        name: "load",
        about: LOAD_ABOUT,
    },
    Subcommand {
        name: "objects",
        about: OBJECTS_ABOUT,
    },
    Subcommand {
        name: "pcr-event",
        about: PCR_EVENT_ABOUT,
    },
    Subcommand {
        name: "pcr-read",
        about: PCR_READ_ABOUT,
    },
    Subcommand {
        name: "policy",
        about: POLICY_ABOUT,
    },
    Subcommand {
        name: "print-error",
        about: PRINT_ERROR_ABOUT,
    },
    Subcommand {
        name: "reset-lock",
        about: RESET_LOCK_ABOUT,
    },
    Subcommand {
        name: "save",
        about: SAVE_ABOUT,
    },
    Subcommand {
        name: "seal",
        about: SEAL_ABOUT,
    },
    Subcommand {
        name: "start-session",
        about: START_SESSION_ABOUT,
    },
    Subcommand {
        name: "unseal",
        about: UNSEAL_ABOUT,
    },
];

struct ArgParser {
    args: std::vec::IntoIter<String>,
}

impl ArgParser {
    fn new(mut args: std::vec::IntoIter<String>) -> Self {
        args.next();
        Self { args }
    }

    fn next(&mut self) -> Option<String> {
        self.args.next()
    }

    fn expect_value(&mut self, option: &str) -> Result<String, TpmError> {
        self.next().ok_or_else(|| {
            TpmError::Execution(format!(
                "argument '{option}' requires a value, but none was supplied"
            ))
        })
    }

    fn expect_positional(&mut self, name: &str) -> Result<String, TpmError> {
        let arg = self.next().ok_or_else(|| {
            TpmError::Execution(format!("missing required positional argument <{name}>"))
        })?;

        if arg.starts_with('-') {
            return Err(TpmError::Execution(format!(
                "found argument '{arg}' instead of positional argument <{name}>"
            )));
        }
        Ok(arg)
    }
}

fn print_usage() {
    let mut output =
        format!("tpm2sh {VERSION}\nTPM 2.0 shell\n\nUSAGE:\n    tpm2sh [OPTIONS] <COMMAND>");
    let opt_items: Vec<(String, &str)> = GLOBAL_OPTIONS
        .iter()
        .map(|(short, long, val, desc)| {
            let mut left = if let Some(s) = short {
                format!("{s}, ")
            } else {
                "   ".to_string()
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
    println!("\nCOMMANDS:");
    for cmd in SUBCOMMANDS {
        println!("    {: <20} {}", cmd.name, cmd.about);
    }
}

fn print_version() {
    println!("tpm2sh {VERSION}");
}

/// Parse command-line arguments.
///
/// # Errors
///
/// Returns a `TpmError::Execute` on a failure.
pub fn parse_cli(args: Args) -> Result<Option<Cli>, TpmError> {
    let mut cli = Cli {
        device: "/dev/tpmrm0".to_string(),
        ..Default::default()
    };
    let mut parser = ArgParser::new(args.collect::<Vec<_>>().into_iter());
    let mut subcommand_arg = None;

    while let Some(arg) = parser.args.clone().next() {
        if !arg.starts_with('-') {
            subcommand_arg = parser.next();
            break;
        }

        parser.next();
        match arg.as_str() {
            "-h" | "--help" => {
                print_main_help();
                return Ok(None);
            }
            "-V" | "--version" => {
                print_version();
                return Ok(None);
            }
            "-d" | "--device" => cli.device = parser.expect_value(&arg)?,
            "--log-format" => cli.log_format = parser.expect_value(&arg)?.parse()?,
            "--session" => cli.session = Some(parser.expect_value(&arg)?),
            "--" => {
                subcommand_arg = parser.next();
                break;
            }
            _ => {
                subcommand_arg = Some(arg);
                break;
            }
        }
    }

    let Some(cmd_name) = subcommand_arg else {
        print_usage();
        return Ok(None);
    };

    cli.command = Some(parse_subcommand(&cmd_name, &mut parser)?);
    Ok(Some(cli))
}

fn parse_subcommand(cmd_name: &str, parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let command = match cmd_name {
        "algorithms" => parse_algorithms(parser)?,
        "convert" => parse_convert(parser)?,
        "create-primary" => parse_create_primary(parser)?,
        "delete" => parse_delete(parser)?,
        "import" => parse_import(parser)?,
        "load" => parse_load(parser)?,
        "objects" => parse_objects(parser)?,
        "pcr-event" => parse_pcr_event(parser)?,
        "pcr-read" => parse_pcr_read(parser)?,
        "policy" => parse_policy(parser)?,
        "print-error" => parse_print_error(parser)?,
        "reset-lock" => parse_reset_lock(parser)?,
        "save" => parse_save(parser)?,
        "seal" => parse_seal(parser)?,
        "start-session" => parse_start_session(parser)?,
        "unseal" => parse_unseal(parser)?,
        "-h" | "--help" => {
            print_main_help();
            std::process::exit(0);
        }
        _ => return Err(TpmError::Execution(format!("unknown command '{cmd_name}'"))),
    };
    Ok(command)
}

fn parse_algorithms(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = Algorithms { filter: None };
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--filter" => args.filter = Some(parser.expect_value(&arg)?),
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "algorithms",
                        ALGORITHMS_ABOUT,
                        ALGORITHMS_USAGE,
                        &[],
                        ALGORITHMS_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    Ok(Commands::Algorithms(args))
}

fn parse_convert(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = Convert::default();
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--from" => args.from = parser.expect_value(&arg)?.parse()?,
            "--to" => args.to = parser.expect_value(&arg)?.parse()?,
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "convert",
                        CONVERT_ABOUT,
                        CONVERT_USAGE,
                        &[],
                        CONVERT_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    Ok(Commands::Convert(args))
}

fn parse_create_primary(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = CreatePrimary::default();
    let mut alg_set = false;
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "-H" | "--hierarchy" => args.hierarchy = parser.expect_value(&arg)?.parse()?,
            "--alg" => {
                args.alg = parser
                    .expect_value(&arg)?
                    .parse()
                    .map_err(TpmError::Parse)?;
                alg_set = true;
            }
            "--persistent" => {
                args.persistent = Some(parse_persistent_handle(&parser.expect_value(&arg)?)?);
            }
            "--auth" => args.auth.auth = Some(parser.expect_value(&arg)?),
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "create-primary",
                        CREATE_PRIMARY_ABOUT,
                        CREATE_PRIMARY_USAGE,
                        &[],
                        CREATE_PRIMARY_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    if !alg_set {
        return Err(TpmError::Execution(
            "the following required arguments were not provided: --alg <ALGORITHM>".to_string(),
        ));
    }
    Ok(Commands::CreatePrimary(args))
}

fn parse_delete(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = Delete::default();
    let mut handle_str = None;
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--auth" => args.auth.auth = Some(parser.expect_value(&arg)?),
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "delete",
                        DELETE_ABOUT,
                        DELETE_USAGE,
                        DELETE_ARGS,
                        DELETE_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ if !arg.starts_with('-') && handle_str.is_none() => {
                handle_str = Some(arg);
            }
            _ => {
                return Err(TpmError::Execution(format!(
                    "unknown or duplicate argument '{arg}'"
                )))
            }
        }
    }
    let handle = handle_str.ok_or_else(|| {
        TpmError::Execution("missing required positional argument <HANDLE>".to_string())
    })?;
    args.handle = parse_hex_u32(&handle)?;
    Ok(Commands::Delete(args))
}

fn parse_import(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = Import::default();
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--auth" => args.parent_auth.auth = Some(parser.expect_value(&arg)?),
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "import",
                        IMPORT_ABOUT,
                        IMPORT_USAGE,
                        &[],
                        IMPORT_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    Ok(Commands::Import(args))
}

fn parse_load(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = Load::default();
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--auth" => args.parent_auth.auth = Some(parser.expect_value(&arg)?),
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help("load", LOAD_ABOUT, LOAD_USAGE, &[], LOAD_OPTIONS)
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    Ok(Commands::Load(args))
}

fn parse_objects(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    if let Some(arg) = parser.next() {
        if arg == "-h" || arg == "--help" {
            println!(
                "{}",
                format_subcommand_help("objects", OBJECTS_ABOUT, OBJECTS_USAGE, &[], &[])
            );
            std::process::exit(0);
        }
        return Err(TpmError::Execution(format!(
            "'objects' takes no arguments, got '{arg}'"
        )));
    }
    Ok(Commands::Objects(Objects {}))
}

fn parse_pcr_event(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = PcrEvent::default();
    let mut data_arg = None;
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--pcr-handle" => args.pcr_handle = parse_hex_u32(&parser.expect_value(&arg)?)?,
            "--auth" => args.auth.auth = Some(parser.expect_value(&arg)?),
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "pcr-event",
                        PCR_EVENT_ABOUT,
                        PCR_EVENT_USAGE,
                        PCR_EVENT_ARGS,
                        PCR_EVENT_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ if !arg.starts_with('-') && data_arg.is_none() => {
                data_arg = Some(arg);
            }
            _ => {
                return Err(TpmError::Execution(format!(
                    "unknown or duplicate argument '{arg}'"
                )))
            }
        }
    }
    args.data = data_arg.ok_or_else(|| {
        TpmError::Execution("missing required positional argument <DATA>".to_string())
    })?;
    Ok(Commands::PcrEvent(args))
}

fn parse_pcr_read(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let selection = parser.expect_positional("SELECTION")?;
    if let Some(arg) = parser.next() {
        if arg == "-h" || arg == "--help" {
            println!(
                "{}",
                format_subcommand_help(
                    "pcr-read",
                    PCR_READ_ABOUT,
                    PCR_READ_USAGE,
                    PCR_READ_ARGS,
                    &[]
                )
            );
            std::process::exit(0);
        }
        return Err(TpmError::Execution(format!("unexpected argument '{arg}'")));
    }
    Ok(Commands::PcrRead(PcrRead { selection }))
}

fn parse_policy(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = Policy::default();
    let mut expression_arg = None;
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--auth" => args.auth.auth = Some(parser.expect_value(&arg)?),
            "-p" | "--partial" => args.partial = true,
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "policy",
                        POLICY_ABOUT,
                        POLICY_USAGE,
                        POLICY_ARGS,
                        POLICY_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ if !arg.starts_with('-') && expression_arg.is_none() => {
                expression_arg = Some(arg);
            }
            _ => {
                return Err(TpmError::Execution(format!(
                    "unknown or duplicate argument '{arg}'"
                )))
            }
        }
    }
    args.expression = expression_arg.ok_or_else(|| {
        TpmError::Execution("missing required positional argument <EXPRESSION>".to_string())
    })?;
    Ok(Commands::Policy(args))
}

fn parse_print_error(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let rc_str = parser.expect_positional("RC")?;
    if let Some(arg) = parser.next() {
        if arg == "-h" || arg == "--help" {
            println!(
                "{}",
                format_subcommand_help(
                    "print-error",
                    PRINT_ERROR_ABOUT,
                    PRINT_ERROR_USAGE,
                    PRINT_ERROR_ARGS,
                    &[]
                )
            );
            std::process::exit(0);
        }
        return Err(TpmError::Execution(format!("unexpected argument '{arg}'")));
    }
    Ok(Commands::PrintError(PrintError {
        rc: parse_tpm_rc(&rc_str)?,
    }))
}

fn parse_reset_lock(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = ResetLock::default();
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--auth" => args.auth.auth = Some(parser.expect_value(&arg)?),
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "reset-lock",
                        RESET_LOCK_ABOUT,
                        RESET_LOCK_USAGE,
                        &[],
                        RESET_LOCK_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    Ok(Commands::ResetLock(args))
}

fn parse_save(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = Save::default();
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--object-handle" => args.object_handle = parse_hex_u32(&parser.expect_value(&arg)?)?,
            "--persistent-handle" => {
                args.persistent_handle = parse_persistent_handle(&parser.expect_value(&arg)?)?;
            }
            "--auth" => args.auth.auth = Some(parser.expect_value(&arg)?),
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help("save", SAVE_ABOUT, SAVE_USAGE, &[], SAVE_OPTIONS)
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    Ok(Commands::Save(args))
}

fn parse_seal(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = Seal::default();
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--auth" => {
                if args.parent_auth.auth.is_none() {
                    args.parent_auth.auth = Some(parser.expect_value(&arg)?);
                } else {
                    args.object_auth.auth = Some(parser.expect_value(&arg)?);
                }
            }
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help("seal", SEAL_ABOUT, SEAL_USAGE, &[], SEAL_OPTIONS)
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    Ok(Commands::Seal(args))
}

fn parse_start_session(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = StartSession::default();
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--session-type" => args.session_type = parser.expect_value(&arg)?.parse()?,
            "--hash-alg" => args.hash_alg = parser.expect_value(&arg)?.parse()?,
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "start-session",
                        START_SESSION_ABOUT,
                        START_SESSION_USAGE,
                        &[],
                        START_SESSION_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    Ok(Commands::StartSession(args))
}

fn parse_unseal(parser: &mut ArgParser) -> Result<Commands, TpmError> {
    let mut args = Unseal::default();
    while let Some(arg) = parser.next() {
        match arg.as_str() {
            "--auth" => args.auth.auth = Some(parser.expect_value(&arg)?),
            "-h" | "--help" => {
                println!(
                    "{}",
                    format_subcommand_help(
                        "unseal",
                        UNSEAL_ABOUT,
                        UNSEAL_USAGE,
                        &[],
                        UNSEAL_OPTIONS
                    )
                );
                std::process::exit(0);
            }
            _ => return Err(TpmError::Execution(format!("unknown argument '{arg}'"))),
        }
    }
    Ok(Commands::Unseal(args))
}
