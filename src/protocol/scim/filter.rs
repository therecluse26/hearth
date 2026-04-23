//! Minimal SCIM filter parser (RFC 7644 §3.4.2.2).
//!
//! This is a deliberately narrow subset — the operators and attributes
//! that Okta and Azure AD actually emit against provisioning endpoints.
//! Anything else (bracketed value filters, `gt`/`lt`/`ge`/`le`, `not`,
//! nested parenthesized groups) is rejected with `invalidFilter`.
//!
//! Supported grammar:
//!
//! ```text
//! filter    ::= term (" or " term)*
//! term      ::= factor (" and " factor)*
//! factor    ::= attr "pr" | attr op literal
//! attr      ::= [a-zA-Z][a-zA-Z0-9_.]*
//! op        ::= "eq" | "ne" | "co" | "sw" | "ew"
//! literal   ::= "\"" string "\"" | "true" | "false" | number
//! ```
//!
//! Attribute names are case-insensitive but retain their input casing so
//! the evaluator can match SCIM's documented attribute names (`userName`,
//! `externalId`, `displayName`, `active`).

use crate::protocol::scim::error::ScimError;
use crate::protocol::scim::types::{ScimGroup, ScimUser};

/// A parsed filter expression, evaluable against a resource.
#[derive(Debug, Clone)]
pub enum FilterExpr {
    /// `attr eq value` — strict equality.
    Eq(String, Value),
    /// `attr ne value` — strict inequality.
    Ne(String, Value),
    /// `attr co value` — substring-contains.
    Co(String, String),
    /// `attr sw value` — starts-with.
    Sw(String, String),
    /// `attr ew value` — ends-with.
    Ew(String, String),
    /// `attr pr` — attribute is present (non-empty).
    Pr(String),
    /// Logical AND.
    And(Box<FilterExpr>, Box<FilterExpr>),
    /// Logical OR.
    Or(Box<FilterExpr>, Box<FilterExpr>),
}

/// A parsed literal value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Quoted string literal.
    Str(String),
    /// Boolean literal (`true` or `false`).
    Bool(bool),
}

/// Parses a SCIM filter string. Returns `invalidFilter` on any parse or
/// unsupported-operator error.
pub fn parse(input: &str) -> Result<FilterExpr, ScimError> {
    let tokens = tokenize(input)?;
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.parse_or()?;
    if parser.pos < parser.tokens.len() {
        return Err(ScimError::invalid_filter("trailing input after filter"));
    }
    Ok(expr)
}

/// Evaluates the filter against a SCIM user.
pub fn matches_user(expr: &FilterExpr, u: &ScimUser) -> bool {
    match expr {
        FilterExpr::Eq(attr, v) => user_attr(u, attr).map_or(false, |s| match v {
            Value::Str(lit) => s.eq_ignore_ascii_case(lit),
            Value::Bool(b) => *s == bool_as_str(*b),
        }),
        FilterExpr::Ne(attr, v) => user_attr(u, attr).map_or(true, |s| match v {
            Value::Str(lit) => !s.eq_ignore_ascii_case(lit),
            Value::Bool(b) => *s != bool_as_str(*b),
        }),
        FilterExpr::Co(attr, lit) => user_attr(u, attr).map_or(false, |s| {
            s.to_ascii_lowercase().contains(&lit.to_ascii_lowercase())
        }),
        FilterExpr::Sw(attr, lit) => user_attr(u, attr).map_or(false, |s| {
            s.to_ascii_lowercase()
                .starts_with(&lit.to_ascii_lowercase())
        }),
        FilterExpr::Ew(attr, lit) => user_attr(u, attr).map_or(false, |s| {
            s.to_ascii_lowercase().ends_with(&lit.to_ascii_lowercase())
        }),
        FilterExpr::Pr(attr) => user_attr(u, attr).is_some_and(|s| !s.is_empty()),
        FilterExpr::And(a, b) => matches_user(a, u) && matches_user(b, u),
        FilterExpr::Or(a, b) => matches_user(a, u) || matches_user(b, u),
    }
}

/// Evaluates the filter against a SCIM group.
pub fn matches_group(expr: &FilterExpr, g: &ScimGroup) -> bool {
    match expr {
        FilterExpr::Eq(attr, v) => group_attr(g, attr).map_or(false, |s| match v {
            Value::Str(lit) => s.eq_ignore_ascii_case(lit),
            Value::Bool(_) => false,
        }),
        FilterExpr::Ne(attr, v) => group_attr(g, attr).map_or(true, |s| match v {
            Value::Str(lit) => !s.eq_ignore_ascii_case(lit),
            Value::Bool(_) => true,
        }),
        FilterExpr::Co(attr, lit) => group_attr(g, attr).map_or(false, |s| {
            s.to_ascii_lowercase().contains(&lit.to_ascii_lowercase())
        }),
        FilterExpr::Sw(attr, lit) => group_attr(g, attr).map_or(false, |s| {
            s.to_ascii_lowercase()
                .starts_with(&lit.to_ascii_lowercase())
        }),
        FilterExpr::Ew(attr, lit) => group_attr(g, attr).map_or(false, |s| {
            s.to_ascii_lowercase().ends_with(&lit.to_ascii_lowercase())
        }),
        FilterExpr::Pr(attr) => group_attr(g, attr).is_some_and(|s| !s.is_empty()),
        FilterExpr::And(a, b) => matches_group(a, g) && matches_group(b, g),
        FilterExpr::Or(a, b) => matches_group(a, g) || matches_group(b, g),
    }
}

fn bool_as_str(b: bool) -> String {
    if b {
        "true".to_string()
    } else {
        "false".to_string()
    }
}

fn user_attr(u: &ScimUser, attr: &str) -> Option<String> {
    match attr.to_ascii_lowercase().as_str() {
        "username" => Some(u.user_name.clone()),
        "externalid" => u.external_id.clone(),
        "displayname" => u.display_name.clone(),
        "active" => Some(bool_as_str(u.active)),
        "id" => u.id.clone(),
        "name.familyname" => u.name.as_ref().and_then(|n| n.family_name.clone()),
        "name.givenname" => u.name.as_ref().and_then(|n| n.given_name.clone()),
        "emails.value" => u
            .emails
            .iter()
            .find(|e| e.primary.unwrap_or(false))
            .or_else(|| u.emails.first())
            .map(|e| e.value.clone()),
        _ => None,
    }
}

fn group_attr(g: &ScimGroup, attr: &str) -> Option<String> {
    match attr.to_ascii_lowercase().as_str() {
        "displayname" => Some(g.display_name.clone()),
        "externalid" => g.external_id.clone(),
        "id" => g.id.clone(),
        _ => None,
    }
}

// ------------ tokenizer ------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Str(String),
    Bool(bool),
    LParen,
    RParen,
}

fn tokenize(s: &str) -> Result<Vec<Tok>, ScimError> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'(' {
            out.push(Tok::LParen);
            i += 1;
            continue;
        }
        if c == b')' {
            out.push(Tok::RParen);
            i += 1;
            continue;
        }
        if c == b'[' || c == b']' {
            return Err(ScimError::invalid_filter(
                "bracketed value filters are not supported",
            ));
        }
        if c == b'"' {
            i += 1;
            let start = i;
            let mut lit = String::new();
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    // Minimal escape handling for \" and \\.
                    let next = bytes[i + 1];
                    lit.push(next as char);
                    i += 2;
                    continue;
                }
                lit.push(bytes[i] as char);
                i += 1;
            }
            if i >= bytes.len() {
                return Err(ScimError::invalid_filter("unterminated string literal"));
            }
            i += 1; // consume closing quote
            let _ = start;
            out.push(Tok::Str(lit));
            continue;
        }
        if c.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.')
            {
                i += 1;
            }
            let ident = std::str::from_utf8(&bytes[start..i])
                .map_err(|_| ScimError::invalid_filter("non-ASCII identifier"))?
                .to_string();
            match ident.as_str() {
                "true" => out.push(Tok::Bool(true)),
                "false" => out.push(Tok::Bool(false)),
                _ => out.push(Tok::Ident(ident)),
            }
            continue;
        }
        return Err(ScimError::invalid_filter(format!(
            "unexpected character '{}' at position {}",
            c as char, i
        )));
    }
    Ok(out)
}

// ------------ parser ------------

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_or(&mut self) -> Result<FilterExpr, ScimError> {
        let mut left = self.parse_and()?;
        while let Some(Tok::Ident(s)) = self.peek() {
            if s.eq_ignore_ascii_case("or") {
                self.bump();
                let right = self.parse_and()?;
                left = FilterExpr::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<FilterExpr, ScimError> {
        let mut left = self.parse_factor()?;
        while let Some(Tok::Ident(s)) = self.peek() {
            if s.eq_ignore_ascii_case("and") {
                self.bump();
                let right = self.parse_factor()?;
                left = FilterExpr::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_factor(&mut self) -> Result<FilterExpr, ScimError> {
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.bump();
            let e = self.parse_or()?;
            match self.bump() {
                Some(Tok::RParen) => Ok(e),
                _ => Err(ScimError::invalid_filter("missing closing parenthesis")),
            }
        } else {
            let attr = match self.bump() {
                Some(Tok::Ident(s)) => s,
                _ => return Err(ScimError::invalid_filter("expected attribute name")),
            };
            let op = match self.bump() {
                Some(Tok::Ident(s)) => s.to_ascii_lowercase(),
                _ => return Err(ScimError::invalid_filter("expected operator")),
            };
            if op == "pr" {
                return Ok(FilterExpr::Pr(attr));
            }
            let val = match self.bump() {
                Some(Tok::Str(s)) => Value::Str(s),
                Some(Tok::Bool(b)) => Value::Bool(b),
                _ => {
                    return Err(ScimError::invalid_filter(
                        "expected string or boolean literal",
                    ))
                }
            };
            match op.as_str() {
                "eq" => Ok(FilterExpr::Eq(attr, val)),
                "ne" => Ok(FilterExpr::Ne(attr, val)),
                "co" => match val {
                    Value::Str(s) => Ok(FilterExpr::Co(attr, s)),
                    _ => Err(ScimError::invalid_filter("co requires string operand")),
                },
                "sw" => match val {
                    Value::Str(s) => Ok(FilterExpr::Sw(attr, s)),
                    _ => Err(ScimError::invalid_filter("sw requires string operand")),
                },
                "ew" => match val {
                    Value::Str(s) => Ok(FilterExpr::Ew(attr, s)),
                    _ => Err(ScimError::invalid_filter("ew requires string operand")),
                },
                other => Err(ScimError::invalid_filter(format!(
                    "unsupported operator '{other}'"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::scim::types::{ScimEmail, ScimName};

    fn user() -> ScimUser {
        ScimUser {
            schemas: vec![],
            id: Some("abc".to_string()),
            external_id: Some("okta-1".to_string()),
            user_name: "alice@example.com".to_string(),
            display_name: Some("Alice Example".to_string()),
            name: Some(ScimName {
                formatted: None,
                given_name: Some("Alice".to_string()),
                family_name: Some("Example".to_string()),
            }),
            emails: vec![ScimEmail {
                value: "alice@example.com".to_string(),
                primary: Some(true),
                r#type: None,
            }],
            active: true,
            meta: None,
        }
    }

    #[test]
    fn eq_username_matches() {
        let expr = parse("userName eq \"alice@example.com\"").expect("parse");
        assert!(matches_user(&expr, &user()));
    }

    #[test]
    fn eq_is_case_insensitive_for_strings() {
        let expr = parse("userName eq \"ALICE@example.com\"").expect("parse");
        assert!(matches_user(&expr, &user()));
    }

    #[test]
    fn pr_detects_presence() {
        let expr = parse("externalId pr").expect("parse");
        assert!(matches_user(&expr, &user()));
        let mut u = user();
        u.external_id = None;
        assert!(!matches_user(&expr, &u));
    }

    #[test]
    fn and_composes() {
        let expr = parse("userName sw \"alice\" and active eq true").expect("parse");
        assert!(matches_user(&expr, &user()));
    }

    #[test]
    fn or_composes() {
        let expr =
            parse("userName eq \"bob\" or userName eq \"alice@example.com\"").expect("parse");
        assert!(matches_user(&expr, &user()));
    }

    #[test]
    fn bracketed_path_rejected() {
        let err =
            parse("emails[type eq \"work\"].value eq \"alice@example.com\"").expect_err("reject");
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn unsupported_op_rejected() {
        let err = parse("userName gt \"x\"").expect_err("reject");
        assert!(err.detail.contains("unsupported"));
    }

    #[test]
    fn active_boolean_literal() {
        let expr = parse("active eq true").expect("parse");
        assert!(matches_user(&expr, &user()));
        let mut u = user();
        u.active = false;
        assert!(!matches_user(&expr, &u));
    }
}
