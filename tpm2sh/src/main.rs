// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use cli::{execute_cli, TpmError};
use log::error;
use std::error::Error;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

    match execute_cli() {
        Ok(()) => {}
        Err(TpmError::HelpDisplayed) => {}
        Err(TpmError::Usage(msg)) => {
            eprintln!("Error: {msg}");
            std::process::exit(1);
        }
        Err(err) => {
            error!("{err}");
            let mut source = err.source();
            while let Some(cause) = source {
                error!("  - {cause}");
                source = cause.source();
            }
            std::process::exit(1);
        }
    }
}
