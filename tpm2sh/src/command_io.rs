// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{cli, AuthSession, TpmError};
use std::io::{BufRead, BufReader, Read, Write};

/// Manages the streaming I/O for a command in the JSON Lines pipeline.
pub struct CommandIo<'a, W: Write> {
    writer: W,
    input_objects: Vec<cli::Object>,
    output_objects: Vec<cli::Object>,
    pub session: Option<&'a AuthSession>,
    pub log_format: cli::LogFormat,
}

impl<'a, W: Write> CommandIo<'a, W> {
    /// Creates a new command context for the pipeline.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if reading from the input stream fails.
    pub fn new<R: Read>(
        reader: R,
        writer: W,
        session: Option<&'a AuthSession>,
        log_format: cli::LogFormat,
    ) -> Result<Self, TpmError> {
        let mut input_objects = Vec::new();
        let buf_reader = BufReader::new(reader);
        for line in buf_reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                input_objects.push(serde_json::from_str(&line)?);
            }
        }
        Ok(Self {
            writer,
            input_objects,
            output_objects: Vec::new(),
            session,
            log_format,
        })
    }

    /// Finds and removes the first object from the input pipeline that matches a predicate.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if no matching object is found.
    pub fn consume_object<F>(&mut self, predicate: F) -> Result<cli::Object, TpmError>
    where
        F: FnMut(&cli::Object) -> bool,
    {
        let pos = self
            .input_objects
            .iter()
            .position(predicate)
            .ok_or_else(|| {
                TpmError::Execution("required object not found in input pipeline".to_string())
            })?;
        Ok(self.input_objects.remove(pos))
    }

    /// Adds an object to be written to the output stream upon finalization.
    pub fn push_object(&mut self, obj: cli::Object) {
        self.output_objects.push(obj);
    }

    /// Finalizes the command, writing all new and unconsumed objects to the output stream.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if JSON serialization or I/O fails.
    pub fn finalize(mut self) -> Result<(), TpmError> {
        let mut final_objects = self.input_objects;
        final_objects.append(&mut self.output_objects);

        for obj in final_objects {
            let json_str = serde_json::to_string(&obj)?;
            writeln!(self.writer, "{json_str}")?;
        }
        Ok(())
    }
}
