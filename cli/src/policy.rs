// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::{char, multispace0},
    combinator::{cut, map},
    error::{context, VerboseError},
    multi::separated_list0,
    sequence::{delimited, preceded, terminated, tuple},
    IResult,
};

/// An Abstract Syntax Tree (AST) for a policy expression.
#[derive(Debug, PartialEq)]
pub enum Policy<'a> {
    Pcr {
        selection_str: &'a str,
        digest_str: &'a str,
    },
    Secret {
        auth_handle_str: &'a str,
    },
    Or(Vec<Policy<'a>>),
}

fn parse_string(input: &str) -> IResult<&str, &str, VerboseError<&str>> {
    context(
        "string",
        preceded(char('\"'), cut(terminated(is_not("\""), char('\"')))),
    )(input)
}

fn parse_pcr(input: &str) -> IResult<&str, Policy, VerboseError<&str>> {
    context(
        "pcr",
        preceded(
            tag("pcr"),
            cut(delimited(
                preceded(multispace0, char('(')),
                map(
                    tuple((
                        preceded(multispace0, is_not(",)")),
                        preceded(char(','), preceded(multispace0, parse_string)),
                    )),
                    |(selection_str, digest_str)| Policy::Pcr {
                        selection_str: selection_str.trim(),
                        digest_str,
                    },
                ),
                preceded(multispace0, char(')')),
            )),
        ),
    )(input)
}

fn parse_secret(input: &str) -> IResult<&str, Policy, VerboseError<&str>> {
    context(
        "secret",
        preceded(
            tag("secret"),
            cut(delimited(
                preceded(multispace0, char('(')),
                map(preceded(multispace0, is_not(")")), |handle_str: &str| {
                    Policy::Secret {
                        auth_handle_str: handle_str.trim(),
                    }
                }),
                preceded(multispace0, char(')')),
            )),
        ),
    )(input)
}

fn parse_or(input: &str) -> IResult<&str, Policy, VerboseError<&str>> {
    context(
        "or",
        preceded(
            tag("or"),
            cut(delimited(
                preceded(multispace0, char('(')),
                map(
                    separated_list0(
                        preceded(multispace0, preceded(char(','), multispace0)),
                        parse_policy,
                    ),
                    Policy::Or,
                ),
                preceded(multispace0, char(')')),
            )),
        ),
    )(input)
}

fn parse_policy(input: &str) -> IResult<&str, Policy, VerboseError<&str>> {
    preceded(multispace0, alt((parse_pcr, parse_secret, parse_or)))(input)
}

/// Top-level parser function that consumes the entire input.
///
/// # Errors
///
/// Returns a descriptive error if parsing fails.
pub fn parse_policy_expression(input: &str) -> Result<Policy, String> {
    match parse_policy(input) {
        Ok((remainder, policy)) => {
            if remainder.trim().is_empty() {
                Ok(policy)
            } else {
                Err(format!("unexpected trailing input: '{remainder}'"))
            }
        }
        Err(nom::Err::Error(e) | nom::Err::Failure(e)) => Err(nom::error::convert_error(input, e)),
        Err(e) => Err(e.to_string()),
    }
}
