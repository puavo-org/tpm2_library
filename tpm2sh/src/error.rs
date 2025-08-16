// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{error::Error, fmt, io::Error as IoError, num::ParseIntError};
use tpm2_protocol::{data::TpmRc, TpmErrorKind};

#[derive(Debug)]
pub enum TpmError {
    Base64(base64::DecodeError),
    Build(TpmErrorKind),
    Der(pkcs8::der::Error),
    Execution(String),
    File(String, IoError),
    Hex(hex::FromHexError),
    InvalidHandle(String),
    Io(IoError),
    Json(serde_json::Error),
    Parse(String),
    ParseInt(ParseIntError),
    PcrSelection(String),
    Pem(pem::PemError),
    Pkcs8(pkcs8::Error),
    TpmRc(TpmRc),
    UnexpectedResponse(String),
}

impl Error for TpmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TpmError::Base64(err) => Some(err),
            TpmError::Der(err) => Some(err),
            TpmError::File(_, err) | TpmError::Io(err) => Some(err),
            TpmError::Hex(err) => Some(err),
            TpmError::Json(err) => Some(err),
            TpmError::ParseInt(err) => Some(err),
            TpmError::Pem(err) => Some(err),
            TpmError::Pkcs8(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::Base64(err) => write!(f, "Base64 decoding failed: {err}"),
            TpmError::Build(err) => write!(f, "Failed to build TPM structure: {err}"),
            TpmError::Der(err) => write!(f, "DER encoding/decoding failed: {err}"),
            TpmError::Execution(reason) => write!(f, "Execution failed: {reason}"),
            TpmError::File(path, err) => write!(f, "File operation failed on '{path}': {err}"),
            TpmError::Hex(err) => write!(f, "Hex decoding failed: {err}"),
            TpmError::InvalidHandle(handle) => write!(f, "Invalid handle: {handle}"),
            TpmError::Io(err) => write!(f, "I/O error: {err}"),
            TpmError::Json(err) => write!(f, "JSON serialization/deserialization failed: {err}"),
            TpmError::Parse(reason) => write!(f, "Parsing failed: {reason}"),
            TpmError::ParseInt(err) => write!(f, "Integer parsing failed: {err}"),
            TpmError::PcrSelection(reason) => write!(f, "Invalid PCR selection: {reason}"),
            TpmError::Pem(err) => write!(f, "PEM parsing failed: {err}"),
            TpmError::Pkcs8(err) => write!(f, "PKCS#8 parsing failed: {err}"),
            TpmError::TpmRc(rc) => write!(f, "TPM returned an error: {rc}"),
            TpmError::UnexpectedResponse(reason) => {
                write!(f, "Unexpected response type from TPM: {reason}")
            }
        }
    }
}

impl From<base64::DecodeError> for TpmError {
    fn from(err: base64::DecodeError) -> Self {
        TpmError::Base64(err)
    }
}

impl From<hex::FromHexError> for TpmError {
    fn from(err: hex::FromHexError) -> Self {
        TpmError::Hex(err)
    }
}

impl From<IoError> for TpmError {
    fn from(err: IoError) -> Self {
        TpmError::Io(err)
    }
}

impl From<ParseIntError> for TpmError {
    fn from(err: ParseIntError) -> Self {
        TpmError::ParseInt(err)
    }
}

impl From<TpmErrorKind> for TpmError {
    fn from(err: TpmErrorKind) -> Self {
        TpmError::Build(err)
    }
}

impl From<indicatif::style::TemplateError> for TpmError {
    fn from(err: indicatif::style::TemplateError) -> Self {
        TpmError::Execution(format!("Spinner template error: {err}"))
    }
}

impl From<pkcs8::der::Error> for TpmError {
    fn from(err: pkcs8::der::Error) -> Self {
        TpmError::Der(err)
    }
}

impl From<serde_json::Error> for TpmError {
    fn from(err: serde_json::Error) -> Self {
        TpmError::Json(err)
    }
}

impl From<pkcs8::Error> for TpmError {
    fn from(err: pkcs8::Error) -> Self {
        TpmError::Pkcs8(err)
    }
}

impl From<pem::PemError> for TpmError {
    fn from(err: pem::PemError) -> Self {
        TpmError::Pem(err)
    }
}
