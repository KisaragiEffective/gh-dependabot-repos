use proc_macro::TokenStream;
use quote::quote;
use std::path::Path;
use syn::{ExprMacro, LitStr, parse_macro_input};

/// Validate a GraphQL document at compile time and return its `&'static str`.
/// Paths are relative to the calling crate's Cargo.toml, rather than its source file.
/// This validates syntax only, not fields or permissions against GitHub's schema.
///
/// ```compile_fail
/// use graphql_query_macro::validate_given_graphql;
/// const QUERY: &str = validate_given_graphql!("query { viewer { login } }");
/// ```
///
/// ```compile_fail
/// use graphql_query_macro::validate_given_graphql;
/// const QUERY: &str = validate_given_graphql!(include_str!("missing.graphql"));
/// ```
///
/// ```compile_fail
/// use graphql_query_macro::validate_given_graphql;
/// const QUERY: &str = validate_given_graphql!(include_str!("tests/fixtures/invalid.graphql"));
/// ```
#[proc_macro]
pub fn validate_given_graphql(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ExprMacro);
    let result = (|| {
        if !input.mac.path.is_ident("include_str") {
            return Err(syn::Error::new_spanned(
                &input,
                "expected include_str!(\"path/to/query.graphql\")",
            ));
        }
        let path: LitStr = syn::parse2(input.mac.tokens.clone())?;
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|error| syn::Error::new(path.span(), error.to_string()))?;
        expand(&path, Path::new(&manifest_dir))
    })();
    result
        .unwrap_or_else(|error| error.to_compile_error())
        .into()
}

fn expand(path: &LitStr, manifest_dir: &Path) -> syn::Result<proc_macro2::TokenStream> {
    let file = manifest_dir.join(path.value());
    let source = std::fs::read_to_string(&file).map_err(|error| {
        syn::Error::new(
            path.span(),
            format!("cannot read GraphQL file {}: {error}", file.display()),
        )
    })?;
    graphql_parser::parse_query::<String>(&source).map_err(|error| {
        syn::Error::new(
            path.span(),
            format!("invalid GraphQL syntax in {}: {error}", file.display()),
        )
    })?;
    let file = file
        .to_str()
        .ok_or_else(|| syn::Error::new(path.span(), "GraphQL path is not UTF-8"))?;
    let file = LitStr::new(file, path.span());
    // Keep the file dependency visible to rustc for incremental rebuilds.
    Ok(quote!(include_str!(#file)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_syntax_has_useful_diagnostic() {
        let path = LitStr::new(
            "tests/fixtures/invalid.graphql",
            proc_macro2::Span::call_site(),
        );
        let error = expand(&path, Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap_err();
        assert!(error.to_string().contains("invalid GraphQL syntax"));
    }
}
