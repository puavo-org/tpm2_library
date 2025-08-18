// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use cli::{execute_cli, TpmError};
use std::error::Error;
use tracing::error;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    match execute_cli() {
        Ok(()) => {}
        Err(TpmError::HelpDisplayed) => {}
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
