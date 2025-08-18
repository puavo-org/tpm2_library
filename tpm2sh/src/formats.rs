// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::TpmError;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct PcrOutput {
    pub update_counter: u32,
    pub banks: BTreeMap<String, BTreeMap<String, String>>,
}

impl PcrOutput {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.banks.values().all(BTreeMap::is_empty)
    }

    #[must_use]
    pub fn to_json(&self) -> json::JsonValue {
        let mut banks_obj = json::object::Object::new();
        for (bank_name, pcrs) in &self.banks {
            let mut pcrs_obj = json::object::Object::new();
            for (pcr_index, digest) in pcrs {
                pcrs_obj.insert(pcr_index, json::JsonValue::String(digest.clone()));
            }
            banks_obj.insert(bank_name, json::JsonValue::Object(pcrs_obj));
        }

        json::object! {
            "update-counter": self.update_counter,
            "banks": banks_obj,
        }
    }

    /// Deserializes a `PcrOutput` from a `json::JsonValue`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Parse` if the JSON object is missing required fields
    /// or contains values of the wrong type.
    pub fn from_json(value: &json::JsonValue) -> Result<Self, TpmError> {
        let update_counter = value["update-counter"]
            .as_u32()
            .ok_or_else(|| TpmError::Parse("missing or invalid 'update-counter'".to_string()))?;

        let mut banks = BTreeMap::new();
        for (bank_name, pcrs_val) in value["banks"].entries() {
            let mut pcrs = BTreeMap::new();
            for (pcr_index, digest_val) in pcrs_val.entries() {
                let digest = digest_val
                    .as_str()
                    .ok_or_else(|| TpmError::Parse("pcr digest is not a string".to_string()))?
                    .to_string();
                pcrs.insert(pcr_index.to_string(), digest);
            }
            banks.insert(bank_name.to_string(), pcrs);
        }

        Ok(Self {
            update_counter,
            banks,
        })
    }
}