// SPDX-License-Identifier: MIT
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use clap::{Parser, Subcommand};
use clap_num::maybe_hex;
use log::{debug, error};
use std::{
    fs::{self, File, OpenOptions},
    io::{Error, ErrorKind, Result},
    os::unix::fs::FileTypeExt,
    path::Path,
};
use tpm2_call::{get_capability, TpmHandle, TpmRc};

/// Holds an open character device file for a TPM chip.
struct TpmChip(File);

impl TpmChip {
    /// Opens the character device for a TPM chip
    pub fn open(path: &str) -> Result<TpmChip> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(Error::from(ErrorKind::InvalidInput));
        }
        let Ok(metadata) = fs::metadata(path) else {
            return Err(Error::from(ErrorKind::InvalidInput));
        };
        if !metadata.file_type().is_char_device() {
            return Err(Error::from(ErrorKind::InvalidInput));
        }
        let Ok(path) = std::fs::canonicalize(path) else {
            return Err(Error::from(ErrorKind::InvalidInput));
        };
        debug!("{}", path.to_str().unwrap());
        Ok(TpmChip(
            OpenOptions::new().read(true).write(true).open(path)?,
        ))
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value = "/dev/tpmrm0")]
    device: String,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decode response code
    TpmRc {
        /// Response code
        #[arg(value_parser = maybe_hex::<u32>)]
        rc: u32,
    },
    /// Enumerate objects
    Objects {
        /// Transient handles
        #[arg(short, long)]
        transient: bool,
        /// Persistent handles
        #[arg(short, long)]
        persistent: bool,
    },
}

const MAX_HANDLES: u32 = 16;

fn main() {
    env_logger::init();
    let cli = Cli::parse();
    match &cli.command {
        Commands::TpmRc { rc } => {
            println!("{} {rc:#010x}", TpmRc::from(*rc));
        }
        Commands::Objects {
            transient,
            persistent,
        } => {
            let mut chip = TpmChip::open(&cli.device).unwrap_or_else(|err| {
                error!("{err}");
                std::process::exit(1);
            });
            if *transient {
                let handles = get_capability(&mut chip.0, TpmHandle::Transient as u32, MAX_HANDLES)
                    .unwrap_or_else(|err| {
                        error!("{err}");
                        std::process::exit(1);
                    });
                for handle in handles {
                    println!("{handle:#010x}");
                }
            }
            if *persistent {
                let handles =
                    get_capability(&mut chip.0, TpmHandle::Persistent as u32, MAX_HANDLES)
                        .unwrap_or_else(|err| {
                            error!("{err}");
                            std::process::exit(1);
                        });
                for handle in handles {
                    println!("{handle:#010x}");
                }
            }
        }
    }
}
