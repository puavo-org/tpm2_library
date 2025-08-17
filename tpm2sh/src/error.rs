// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{io::Error as IoError, num::ParseIntError};
use thiserror::Error;
use tpm2_protocol::{data::TpmRc, TpmErrorKind};

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("Failed to build TPM structure: {0}")]
    Build(TpmErrorKind),

    #[error("Execution failed: {0}")]
    Execution(String),

    #[error("File operation on '{0}': {1}")]
    File(String, #[source] IoError),

    #[error("Invalid handle: {0}")]
    InvalidHandle(String),

    #[error("I/O error: {0}")]
    Io(#[from] IoError),

    #[error("JSON operation failed: {0}")]
    Json(#[from] json::Error),

    #[error("Argument parsing failed: {0}")]
    Lexopt(#[from] lexopt::Error),

    #[error("Parsing failed: {0}")]
    Parse(String),

    #[error("Invalid PCR selection: {0}")]
    PcrSelection(String),

    #[error("TPM returned an error: {0}")]
    TpmRc(TpmRc),

    #[error("Unexpected response type from TPM: {0}")]
    UnexpectedResponse(String),
}

impl From<base64::DecodeError> for TpmError {
    fn from(err: base64::DecodeError) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<hex::FromHexError> for TpmError {
    fn from(err: hex::FromHexError) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<ParseIntError> for TpmError {
    fn from(err: ParseIntError) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<indicatif::style::TemplateError> for TpmError {
    fn from(err: indicatif::style::TemplateError) -> Self {
        TpmError::Execution(format!("Spinner template error: {err}"))
    }
}

impl From<pkcs8::der::Error> for TpmError {
    fn from(err: pkcs8::der::Error) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<pkcs8::Error> for TpmError {
    fn from(err: pkcs8::Error) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<pem::PemError> for TpmError {
    fn from(err: pem::PemError) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<TpmErrorKind> for TpmError {
    fn from(err: TpmErrorKind) -> Self {
        TpmError::Build(err)
    }
}
