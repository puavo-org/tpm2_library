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
            _ => None,
        }
    }
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::Base64(err) => write!(f, "error=base64, details='{err}'"),
            TpmError::Build(err) => write!(f, "error=build, details='{err}'"),
            TpmError::Der(err) => write!(f, "error=der, details='{err}'"),
            TpmError::Execution(reason) => write!(f, "error=cli, reason='{reason}'"),
            TpmError::File(path, err) => write!(f, "error=io, path={path}, details='{err}'"),
            TpmError::Hex(err) => write!(f, "error=hex, details='{err}'"),
            TpmError::InvalidHandle(handle) => {
                write!(f, "error=cli, reason='invalid handle: {handle}'")
            }
            TpmError::Io(err) => write!(f, "error=io, details='{err}'"),
            TpmError::Json(err) => write!(f, "error=json, details='{err}'"),
            TpmError::Parse(reason) => write!(f, "error=parse, reason='{reason}'"),
            TpmError::ParseInt(err) => write!(f, "error=parse, details='{err}'"),
            TpmError::PcrSelection(reason) => write!(f, "error=pcr, reason='{reason}'"),
            TpmError::TpmRc(rc) => write!(f, "error=tpm, rc='{rc}'"),
            TpmError::UnexpectedResponse(reason) => {
                write!(f, "error=cli, reason='unexpected response type: {reason}'")
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
        TpmError::Parse(err.to_string())
    }
}

impl From<pem::PemError> for TpmError {
    fn from(err: pem::PemError) -> Self {
        TpmError::Parse(err.to_string())
    }
}
