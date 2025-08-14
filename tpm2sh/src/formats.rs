// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PcrOutput {
    #[serde(rename = "update-counter")]
    pub update_counter: u32,
    pub banks: BTreeMap<String, BTreeMap<String, String>>,
}
