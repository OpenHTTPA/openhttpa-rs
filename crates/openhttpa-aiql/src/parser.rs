// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use crate::{AiqlPolicy, Condition};
use serde_json::Error as SerdeError;
use winnow::ascii::space0;
use winnow::combinator::{alt, delimited, separated};
use winnow::prelude::*;
use winnow::token::{literal, take_while};

pub struct AiqlParser;

impl AiqlParser {
    pub fn parse_json(json: &str) -> Result<AiqlPolicy, SerdeError> {
        serde_json::from_str(json)
    }

    pub fn parse_dsl(dsl: &str) -> Result<Condition, String> {
        let mut input = dsl;
        parse_condition(&mut input).map_err(|e| e.to_string())
    }
}

fn parse_field<'a>(input: &mut &'a str) -> winnow::Result<&'a str> {
    take_while(1.., |c: char| c.is_alphanumeric() || c == '.' || c == '_').parse_next(input)
}

fn parse_string<'a>(input: &mut &'a str) -> winnow::Result<&'a str> {
    delimited('"', take_while(0.., |c: char| c != '"'), '"').parse_next(input)
}

fn parse_primitive(input: &mut &str) -> winnow::Result<Condition> {
    let field = parse_field(input)?;
    let _ = space0(input)?;
    let op =
        alt((literal("=="), literal("contains"), literal("not contains"))).parse_next(input)?;
    let _ = space0(input)?;
    let value = parse_string(input)?;

    match op {
        "==" => Ok(Condition::Equals {
            field: field.to_owned(),
            value: value.to_owned(),
        }),
        "contains" => Ok(Condition::Contains {
            field: field.to_owned(),
            value: value.to_owned(),
        }),
        "not contains" => Ok(Condition::NotContains {
            field: field.to_owned(),
            value: value.to_owned(),
        }),
        _ => unreachable!(),
    }
}

fn parse_condition(input: &mut &str) -> winnow::Result<Condition> {
    let _ = space0(input)?;
    let mut or_conds: Vec<Condition> =
        separated(1.., parse_and_condition, (space0, literal("OR"), space0)).parse_next(input)?;
    if or_conds.len() == 1 {
        Ok(or_conds.pop().unwrap())
    } else {
        Ok(Condition::Or(or_conds))
    }
}

fn parse_and_condition(input: &mut &str) -> winnow::Result<Condition> {
    let mut and_conds: Vec<Condition> = separated(
        1..,
        parse_primitive_or_paren,
        (space0, literal("AND"), space0),
    )
    .parse_next(input)?;
    if and_conds.len() == 1 {
        Ok(and_conds.pop().unwrap())
    } else {
        Ok(Condition::And(and_conds))
    }
}

fn parse_primitive_or_paren(input: &mut &str) -> winnow::Result<Condition> {
    alt((
        delimited(
            (literal("("), space0),
            parse_condition,
            (space0, literal(")")),
        ),
        parse_primitive,
    ))
    .parse_next(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dsl() {
        let query = "caller.did == \"did:foo\" AND intent contains \"transfer\"";
        let cond = AiqlParser::parse_dsl(query).unwrap();
        assert_eq!(
            cond,
            Condition::And(vec![
                Condition::Equals {
                    field: "caller.did".to_owned(),
                    value: "did:foo".to_owned()
                },
                Condition::Contains {
                    field: "intent".to_owned(),
                    value: "transfer".to_owned()
                }
            ])
        );
    }
}
