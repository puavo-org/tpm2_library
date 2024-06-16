// SPDX-License-Identifier: MIT
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use bincode::{config::DefaultOptions, Options};
use clap::{Parser, Subcommand};
use clap_num::maybe_hex;
use log::{debug, error};
use std::{
    fs::{self, OpenOptions},
    io::{Error, ErrorKind, Read, Result, Write},
    os::unix::fs::FileTypeExt,
    path::Path,
};
use tpm2_call::{Capability, TpmCc, TpmRc, TpmTag, HR_PERSISTENT, HR_TRANSIENT};

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

fn is_char_device(path: &str) -> bool {
    let path = Path::new(path);
    if !path.exists() {
        return false;
    }
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    metadata.file_type().is_char_device()
}

fn write_get_handles_command<T>(file: &mut T, property: u32, property_count: u32) -> Result<()>
where
    T: Write,
{
    let mut buf = vec![];
    let target = DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian();
    buf.extend(&target.serialize(&(TpmTag::NoSessions as u16)).unwrap());
    buf.extend(&target.serialize(&22_u32).unwrap());
    buf.extend(&target.serialize(&(TpmCc::GetCapability as u32)).unwrap());
    buf.extend(&target.serialize(&(Capability::Handles as u32)).unwrap());
    buf.extend(&target.serialize(&property).unwrap());
    buf.extend(&target.serialize(&property_count).unwrap());
    file.write_all(&buf)?;
    Ok(())
}

fn read_get_handles_response<T>(
    file: &mut T,
    handles: &mut Vec<u32>,
    property_count_max: u32,
) -> Result<()>
where
    T: Read,
{
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    // Check that the static part of the header for `TPM2_GetCapability` takes
    // exactly 19 bytes and the tail should be a multiple of the handle size. If
    // these conditions are not met, the data will be corrupted.
    if buf.len() < 19 || ((buf.len() - 19) & 0x03) != 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    let response_size: usize = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
    // Check that the response header contains matching size with the total size
    // of the received data.
    if response_size != buf.len() {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    debug!("response size: {response_size}");
    let handles_count = u32::from_be_bytes([buf[15], buf[16], buf[17], buf[18]]) as usize;
    if handles_count != ((buf.len() - 19) >> 2) {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if handles_count > property_count_max as usize {
        return Err(Error::from(ErrorKind::OutOfMemory));
    }
    for i in 0..handles_count {
        let j: usize = i + 19;
        let handle = u32::from_be_bytes([buf[j], buf[j + 1], buf[j + 2], buf[j + 3]]);
        handles.push(handle);
    }
    Ok(())
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
            if !is_char_device(&cli.device) {
                error!("invalid device");
                std::process::exit(1);
            }
            let Ok(device) = std::fs::canonicalize(&cli.device) else {
                error!("invalid device");
                std::process::exit(1);
            };
            if let Some(device) = device.to_str() {
                debug!("device: {device}");
            }
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(device)
                .unwrap_or_else(|err| {
                    error!("{err}");
                    std::process::exit(1);
                });
            if *transient {
                write_get_handles_command(&mut file, HR_TRANSIENT, MAX_HANDLES).unwrap_or_else(
                    |err| {
                        error!("{err}");
                        std::process::exit(1);
                    },
                );
                let mut handles = vec![];
                read_get_handles_response(&mut file, &mut handles, MAX_HANDLES).unwrap_or_else(
                    |err| {
                        error!("{err}");
                        std::process::exit(1);
                    },
                );
                for handle in handles {
                    println!("{handle:#010x}");
                }
            }
            if *persistent {
                write_get_handles_command(&mut file, HR_PERSISTENT, MAX_HANDLES).unwrap_or_else(
                    |err| {
                        error!("{err}");
                        std::process::exit(1);
                    },
                );
                let mut handles = vec![];
                read_get_handles_response(&mut file, &mut handles, MAX_HANDLES).unwrap_or_else(
                    |err| {
                        error!("{err}");
                        std::process::exit(1);
                    },
                );
                for handle in handles {
                    println!("{handle:#010x}");
                }
            }
        }
    }
}
