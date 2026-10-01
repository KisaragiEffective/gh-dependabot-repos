use graphql_query_macro::validate_given_graphql;

const QUERY: &str = validate_given_graphql!(include_str!("tests/fixtures/valid.graphql"));

#[test]
fn returns_original_document() {
    assert_eq!(QUERY, include_str!("fixtures/valid.graphql"));
}
