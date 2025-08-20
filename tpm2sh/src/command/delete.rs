// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Commands, Delete, Object},
    get_auth_sessions, parse_args, parse_hex_u32, Command, CommandIo, TpmDevice, TpmError,
};
use lexopt::prelude::*;
use tpm2_protocol::{
    data::TpmRh,
    message::{TpmEvictControlCommand, TpmFlushContextCommand},
    TpmPersistent, TpmTransient,
};

const ABOUT: &str = "Deletes a transient or persistent object";
const USAGE: &str = "tpm2sh delete [OPTIONS] <HANDLE>";
const ARGS: &[CommandLineArgument] = &[(
    "HANDLE",
    "Handle of the object to delete, or '-' to read from stdin",
)];
const OPTIONS: &[CommandLineOption] = &[
    (None, "--auth", "<AUTH>", "Authorization value"),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Delete {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("delete", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Delete::default();
        let mut handle_arg = None;

        parse_args!(parser, arg, Self::help, {
            Long("auth") => {
                args.auth.auth = Some(parser.value()?.string()?);
            }
            Value(val) if handle_arg.is_none() => {
                handle_arg = Some(val.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });

        if let Some(handle) = handle_arg {
            args.handle = handle;
            Ok(Commands::Delete(args))
        } else {
            Self::help();
            Err(TpmError::HelpDisplayed)
        }
    }

    /// Runs `delete`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(
        &self,
        device: &mut Option<TpmDevice>,
        log_format: cli::LogFormat,
    ) -> Result<(), TpmError> {
        let chip = device.as_mut().unwrap();
        let mut io = CommandIo::new(std::io::stdout(), log_format)?;
        let session = io.take_session()?;

        let handle = if self.handle == "-" {
            let obj = io.consume_object(|_| true)?;
            let Object::TpmObject(hex_string) = obj;
            parse_hex_u32(&hex_string)?
        } else {
            parse_hex_u32(&self.handle)?
        };

        if handle >= TpmRh::PersistentFirst as u32 {
            let persistent_handle = TpmPersistent(handle);
            let auth_handle = TpmRh::Owner;
            let handles = [auth_handle as u32, persistent_handle.into()];
            let evict_cmd = TpmEvictControlCommand {
                auth: (auth_handle as u32).into(),
                object_handle: persistent_handle.0.into(),
                persistent_handle,
            };
            let sessions = get_auth_sessions(
                &evict_cmd,
                &handles,
                session.as_ref(),
                self.auth.auth.as_deref(),
            )?;
            let (resp, _) = chip.execute(&evict_cmd, Some(&[]), &sessions, log_format)?;
            resp.EvictControl()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            println!("{persistent_handle:#010x}");
        } else if handle >= TpmRh::TransientFirst as u32 {
            let flush_handle = TpmTransient(handle);
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: flush_handle.into(),
            };
            let (resp, _) = chip.execute(&flush_cmd, Some(&[]), &[], log_format)?;
            resp.FlushContext()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            println!("{flush_handle:#010x}");
        } else {
            return Err(TpmError::InvalidHandle(format!(
                "'{handle:#010x}' is not a transient or persistent handle"
            )));
        }
        Ok(())
    }
}
