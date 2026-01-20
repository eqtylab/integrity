use anyhow::{anyhow, bail, Result};
use cel::{
    common::{ast::Expr, value::CelVal},
    IdedExpr,
};
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};

/// A filter that can be applied when retrieving a collection of statements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum StatementFilter {
    /// Filter by exact statement type match
    StatementTypeEquals(String),
    /// Filter by exact attribute value match
    AttributeEquals((String, Value)),
    /// Filter by attribute value less than threshold
    AttributeLessThan((String, Number)),
    /// Filter by attribute value greater than threshold
    AttributeGreaterThan((String, Number)),
    /// Combine filters with AND logic
    And(Vec<Self>),
    /// Combine filters with OR logic
    Or(Vec<Self>),
    /// Negate a filter with NOT logic
    Not(Box<Self>),
}

static SUPPORTED_IDENTIFIERS_MSG: &str = "Supported identifiers: 'statementType'";
static SUPPORTED_SELECT_EXPRESSION_MSG: &str = "Supported select expressions: 'attributes.<key>'";

impl StatementFilter {
    /// Parses a CEL (Common Expression Language) query string into a StatementFilter.
    ///
    /// # Arguments
    /// * `expr` - CEL expression string (e.g., "statementType == 'DataRegistration'")
    ///
    /// # Returns
    /// * `Result<Self>` - Parsed filter, or error if the expression is invalid
    pub fn parse_query(expr: &str) -> Result<Self> {
        let IdedExpr { expr, .. } = cel::parser::Parser::new().parse(expr)?;

        let filter = Self::try_from_cel_expr(&expr)?;

        Ok(filter)
    }

    fn try_from_cel_expr(expr: &Expr) -> Result<Self> {
        log::debug!("Parsing CEL expression: {:?}", expr);

        enum FilterConditionalLeftSide {
            StatementType,
            Attribute(String),
        }

        let filter = match expr {
            // UnspecifiedExprKind represents an unset expression with no specified properties.
            Expr::Unspecified => {
                bail!("Unspecified expressions are not supported as top-level expressions")
            }
            // CallKind represents a function call.
            Expr::Call(call) => {
                match call.func_name.as_str() {
                    "_==_" | "_!=_" | "_>_" | "_<_" => {
                        let operand = call.func_name.as_str();

                        if call.args.len() != 2 {
                            bail!("Expected 2 arguments for '=='");
                        }
                        let left = &call.args[0];
                        let right = &call.args[1];

                        // Left should be an identifier ("statementType") or select expression ("attributes.myStringTag")
                        let left = match &left.expr {
                            Expr::Ident(ident) => match ident.as_str() {
                                "statementType" => FilterConditionalLeftSide::StatementType,
                                _ => bail!("Unsupported identifier on left side of {operand}. {SUPPORTED_IDENTIFIERS_MSG}"),
                            },
                            Expr::Select(select) => match &select.operand.expr {
                                Expr::Ident(ident) => {
                                    if ident == "attributes" {
                                        FilterConditionalLeftSide::Attribute(select.field.clone())
                                    } else {
                                        bail!("Unsupported select expression on left side of {operand}. {SUPPORTED_SELECT_EXPRESSION_MSG}");
                                    }
                                }
                                _ => bail!(
                                    "Left side of {operand} must be an identifier or select expression. {SUPPORTED_IDENTIFIERS_MSG}. {SUPPORTED_SELECT_EXPRESSION_MSG}"
                                ),
                            },
                            _ => bail!(
                                "Left side of {operand} must be an identifier or select expression. {SUPPORTED_IDENTIFIERS_MSG}. {SUPPORTED_SELECT_EXPRESSION_MSG}"
                            ),
                        };

                        // Right should be a literal
                        let right = if let Expr::Literal(lit) = &right.expr {
                            match lit {
                                CelVal::String(s) => Value::String(s.clone()),
                                CelVal::Double(d) => Value::Number(
                                    Number::from_f64(*d)
                                        .ok_or_else(|| anyhow!("Invalid f64 value"))?,
                                ),
                                CelVal::Int(i) => Value::Number(Number::from(*i)),
                                CelVal::UInt(u) => Value::Number(Number::from(*u)),
                                _ => bail!(
                                    "Strings and numbers are the only supported literal types"
                                ),
                            }
                        } else {
                            bail!("Right side of {operand} must be a literal");
                        };

                        let filter = match (left, operand, right) {
                            (
                                FilterConditionalLeftSide::StatementType,
                                "_==_" | "_!=_",
                                Value::String(statement_type),
                            ) => StatementFilter::StatementTypeEquals(statement_type),
                            (FilterConditionalLeftSide::Attribute(key), "_==_" | "_!=_", value) => {
                                StatementFilter::AttributeEquals((key, value))
                            }
                            (
                                FilterConditionalLeftSide::Attribute(key),
                                "_>_",
                                Value::Number(n),
                            ) => StatementFilter::AttributeGreaterThan((key, n)),
                            (
                                FilterConditionalLeftSide::Attribute(key),
                                "_<_",
                                Value::Number(n),
                            ) => StatementFilter::AttributeLessThan((key, n)),
                            _ => bail!("Invalid left/right side combination for {operand}"),
                        };

                        if operand == "_!=_" {
                            StatementFilter::Not(Box::new(filter))
                        } else {
                            filter
                        }
                    }
                    "_&&_" => StatementFilter::And(
                        call.args
                            .iter()
                            .map(|arg| Self::try_from_cel_expr(&arg.expr))
                            .collect::<Result<Vec<_>>>()?,
                    ),
                    "_||_" => StatementFilter::Or(
                        call.args
                            .iter()
                            .map(|arg| Self::try_from_cel_expr(&arg.expr))
                            .collect::<Result<Vec<_>>>()?,
                    ),
                    "!_" => match &call.args[..] {
                        [arg] => {
                            StatementFilter::Not(Box::new(Self::try_from_cel_expr(&arg.expr)?))
                        }
                        _ => bail!("Expected 1 argument for '!'"),
                    },
                    _ => bail!("Unsupported function call: {}", call.func_name),
                }
            }
            // ComprehensionKind represents a comprehension expression generated by a macro.
            Expr::Comprehension(_) => {
                bail!("Comprehension expressions are not supported as top-level expressions")
            }
            // IdentKind represents a simple variable, constant, or type identifier.
            Expr::Ident(_) => {
                bail!("Identifier expressions are not supported as top-level expressions")
            }
            // ListKind represents a list literal expression.
            Expr::List(_) => bail!("List expressions are not supported as top-level expressions"),
            // LiteralKind represents a primitive scalar literal.
            Expr::Literal(_) => {
                bail!("Literal expressions are not supported as top-level expressions")
            }
            // MapKind represents a map literal expression.
            Expr::Map(_) => bail!("Map expressions are not supported as top-level expressions"),
            // SelectKind represents a field selection expression.
            Expr::Select(_) => {
                bail!("Select expressions are not supported as top-level expressions")
            }
            // StructKind represents a struct literal expression.
            Expr::Struct(_) => {
                bail!("Struct expressions are not supported as top-level expressions")
            }
        };

        Ok(filter)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_statement_type_equals() {
        // env_logger::builder().is_test(true).try_init().ok();

        assert_eq!(
            StatementFilter::parse_query("statementType == 'DataRegistration'").unwrap(),
            StatementFilter::StatementTypeEquals("DataRegistration".to_owned())
        );

        assert_eq!(
            StatementFilter::parse_query("statementType == \"DataRegistration\"").unwrap(),
            StatementFilter::StatementTypeEquals("DataRegistration".to_owned())
        );
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_attribute_equals() {
        // env_logger::builder().is_test(true).try_init().ok();

        assert_eq!(
            StatementFilter::parse_query("attributes.myStringTag == 'MyTagValue'").unwrap(),
            StatementFilter::AttributeEquals(("myStringTag".to_owned(), json!("MyTagValue"),))
        );

        assert_eq!(
            StatementFilter::parse_query("attributes.myUIntTag == 42").unwrap(),
            StatementFilter::AttributeEquals(("myUIntTag".to_owned(), json!(42),))
        );

        assert_eq!(
            StatementFilter::parse_query("attributes.myIntTag == -42").unwrap(),
            StatementFilter::AttributeEquals(("myIntTag".to_owned(), json!(-42),))
        );

        assert_eq!(
            StatementFilter::parse_query("attributes.myDoubleTag == 3.14").unwrap(),
            StatementFilter::AttributeEquals(("myDoubleTag".to_owned(), json!(3.14),))
        );
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_attribute_greater_than() {
        // env_logger::builder().is_test(true).try_init().ok();

        assert_eq!(
            StatementFilter::parse_query("attributes.myUIntTag > 42").unwrap(),
            StatementFilter::AttributeGreaterThan(("myUIntTag".to_owned(), Number::from(42)))
        );

        assert_eq!(
            StatementFilter::parse_query("attributes.myIntTag > -42").unwrap(),
            StatementFilter::AttributeGreaterThan(("myIntTag".to_owned(), Number::from(-42)))
        );

        assert_eq!(
            StatementFilter::parse_query("attributes.myDoubleTag > 3.14").unwrap(),
            StatementFilter::AttributeGreaterThan((
                "myDoubleTag".to_owned(),
                Number::from_f64(3.14).unwrap()
            ))
        );
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_attribute_less_than() {
        // env_logger::builder().is_test(true).try_init().ok();

        assert_eq!(
            StatementFilter::parse_query("attributes.myUIntTag < 42").unwrap(),
            StatementFilter::AttributeLessThan(("myUIntTag".to_owned(), Number::from(42)))
        );

        assert_eq!(
            StatementFilter::parse_query("attributes.myIntTag < -42").unwrap(),
            StatementFilter::AttributeLessThan(("myIntTag".to_owned(), Number::from(-42)))
        );

        assert_eq!(
            StatementFilter::parse_query("attributes.myDoubleTag < 3.14").unwrap(),
            StatementFilter::AttributeLessThan((
                "myDoubleTag".to_owned(),
                Number::from_f64(3.14).unwrap()
            ))
        );
    }

    #[test]
    fn test_and() {
        // env_logger::builder().is_test(true).try_init().ok();

        assert_eq!(
            StatementFilter::parse_query(
                "statementType == 'DataRegistration' && attributes.myStringTag == 'MyTagValue'"
            )
            .unwrap(),
            StatementFilter::And(vec![
                StatementFilter::StatementTypeEquals("DataRegistration".to_owned()),
                StatementFilter::AttributeEquals(("myStringTag".to_owned(), json!("MyTagValue"),))
            ])
        );
    }

    #[test]
    fn test_or() {
        // env_logger::builder().is_test(true).try_init().ok();

        assert_eq!(
            StatementFilter::parse_query(
                "statementType == 'DataRegistration' || attributes.myStringTag == 'MyTagValue'"
            )
            .unwrap(),
            StatementFilter::Or(vec![
                StatementFilter::StatementTypeEquals("DataRegistration".to_owned()),
                StatementFilter::AttributeEquals(("myStringTag".to_owned(), json!("MyTagValue"),))
            ])
        );
    }

    #[test]
    fn test_not() {
        // env_logger::builder().is_test(true).try_init().ok();

        assert_eq!(
            StatementFilter::parse_query("!(statementType == 'DataRegistration')").unwrap(),
            StatementFilter::Not(Box::new(StatementFilter::StatementTypeEquals(
                "DataRegistration".to_owned()
            )))
        );
    }

    #[test]
    fn test_nested() {
        // env_logger::builder().is_test(true).try_init().ok();

        assert_eq!(
            StatementFilter::parse_query("(statementType == 'DataRegistration' && attributes.myStringTag == 'MyTagValue') || attributes.myUIntTag > 42").unwrap(),
            StatementFilter::Or(vec![
                StatementFilter::And(vec![
                    StatementFilter::StatementTypeEquals("DataRegistration".to_owned()),
                    StatementFilter::AttributeEquals(("myStringTag".to_owned(), json!("MyTagValue"),))
                ]),
                StatementFilter::AttributeGreaterThan(("myUIntTag".to_owned(), Number::from(42)))
            ])
        );
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_complex() {
        // env_logger::builder().is_test(true).try_init().ok();

        assert_eq!(
            StatementFilter::parse_query("!(statementType == 'DataRegistration' && (attributes.myStringTag == 'MyTagValue' || attributes.myUIntTag > 42)) || attributes.myDoubleTag < 3.14").unwrap(),
            StatementFilter::Or(vec![
                StatementFilter::Not(Box::new(StatementFilter::And(vec![
                    StatementFilter::StatementTypeEquals("DataRegistration".to_owned()),
                    StatementFilter::Or(vec![
                        StatementFilter::AttributeEquals(("myStringTag".to_owned(), json!("MyTagValue"),)),
                        StatementFilter::AttributeGreaterThan(("myUIntTag".to_owned(), Number::from(42)))
                    ])
                ]))),
                StatementFilter::AttributeLessThan(("myDoubleTag".to_owned(), Number::from_f64(3.14).unwrap()))
            ])
        );
    }
}
