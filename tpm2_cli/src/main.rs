// SPDX-License-Identifier: MIT

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use clap::{Parser, Subcommand};
use clap_num::maybe_hex;
use tpm2_call::ReturnCode;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decode TPM 2.0 return code
    Rc {
        /// Return code
        #[arg(value_parser = maybe_hex::<u16>)]
        rc: u16,
    },
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Rc { rc } => {
            let out_rc = ReturnCode::try_from(*rc);
            if let Ok(out_rc) = out_rc {
                println!("{out_rc}");
            } else {
                println!(); // N/A
            }
        }
    }
}
