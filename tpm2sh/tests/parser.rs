// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use cli::{
    command::policy::{PolicyParser, Rule as PolicyRule},
    PcrSelectionParser, Rule as PcrSelectionRule,
};
use pest::Parser;
use rstest::rstest;

#[rstest]
#[case("sha1:0")]
#[case("sha256:0,1,23")]
#[case("sha384:15")]
#[case("sha1:0+sha256:1,2")]
#[case("sha1:0+sha256:1,2+sha384:3,4,5")]
fn test_pcr_selection_parser_valid(#[case] input: &str) {
    assert!(PcrSelectionParser::parse(PcrSelectionRule::selection, input).is_ok());
}

#[rstest]
#[case("sha1")]
#[case("sha256:")]
#[case("sha1:0,,1")]
#[case("sha1:0,")]
#[case("sha1:a")]
#[case("sha256:0+")]
#[case("foo:1")]
#[case("sha256: 0")]
fn test_pcr_selection_parser_invalid(#[case] input: &str) {
    assert!(PcrSelectionParser::parse(PcrSelectionRule::selection, input).is_err());
}

#[rstest]
#[case("pcr(\"sha256:0\")")]
#[case("pcr(\"sha1:0,15\", \"deadbeef\")")]
#[case("pcr(\"sha256:23\", \"cafebabe\", count=123)")]
#[case("secret(\"0x40000001\")")]
#[case("or(pcr(\"sha256:0\"), secret(\"0x40000001\"))")]
#[case("or(pcr(\"s:0\"), pcr(\"s:1\"), pcr(\"s:2\"))")]
#[case("or(pcr(\"s:0\"), or(secret(\"h:1\"), pcr(\"s:2\")))")]
fn test_policy_parser_valid(#[case] input: &str) {
    PolicyParser::parse(PolicyRule::policy_expression, input).expect(input);
}

#[rstest]
#[case("pcr()")]
#[case("pcr(\"sha256:0\",)")]
#[case("pcr(\"sha256:0\", ,\"deadbeef\")")]
#[case("pcr(\"sha256:0\", \"deadbeef\", count=)")]
#[case("pcr(\"sha256:0\", \"deadbeef\", count=abc)")]
#[case("secret()")]
#[case("or()")]
#[case("or(pcr(\"s:0\"))")]
#[case("or(pcr(\"s:0\"), )")]
#[case("foo(\"bar\")")]
#[case("pcr(\"unterminated string)")]
fn test_policy_parser_invalid(#[case] input: &str) {
    assert!(PolicyParser::parse(PolicyRule::policy_expression, input).is_err());
}
