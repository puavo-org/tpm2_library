// SPDX-License-Identifier: MIT

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use clap::{Parser, Subcommand};
use clap_num::maybe_hex;
use tpm2_call::ResponseCode;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decode response code
    ResponseCode {
        /// Response code
        #[arg(value_parser = maybe_hex::<u32>)]
        rc: u32,
    },
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::ResponseCode { rc } => {
            let out_rc = ResponseCode::try_from(*rc);
            if let Ok(out_rc) = out_rc {
                println!("{out_rc}");
            } else {
                println!("unknown {rc:#010x}");
            }
        }
    }
}
