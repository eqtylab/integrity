use std::collections::HashMap;

use anyhow::{anyhow, Result};
use futures::future::{BoxFuture, FutureExt};
use iref::IriBuf;
use json_ld::{loader::Loader, syntax, syntax::Parse, RemoteDocument};
use locspan::Span;
use log::{debug, trace};
use once_cell::sync::OnceCell;
use rdf_types::vocabulary::IriVocabularyMut;

type ContextMap = HashMap<String, &'static str>;

/// JSON-LD context loader for resolving context URIs to their definitions.
///
/// Loads contexts from static embedded definitions or additional runtime contexts,
/// enabling JSON-LD document expansion without network requests.
#[derive(Clone)]
pub struct ContextLoader {
    static_context_map: &'static ContextMap,
    additional_contexts: HashMap<String, String>,
}

impl Loader<IriBuf, Span> for ContextLoader {
    type Output = syntax::Value<Span>;
    type Error = anyhow::Error;

    fn load_with<'a>(
        &'a mut self,
        _vocabulary: &'a mut (impl Sync + Send + IriVocabularyMut<Iri = IriBuf>),
        url: IriBuf,
    ) -> BoxFuture<'a, json_ld::LoadingResult<IriBuf, Span, Self::Output, Self::Error>>
    where
        IriBuf: 'a,
    {
        async move {
            let link = url.as_str();

            debug!("Loading context: {link}");

            let context_str: &str = if let Some(ctx) = self.additional_contexts.get(link) {
                ctx.as_str()
            } else if let Some(ctx) = self.static_context_map.get(link) {
                ctx
            } else {
                return Err(anyhow!("Missing context: {}", url.as_str()));
            };

            trace!("Context: {context_str}");

            let context_document = RemoteDocument::new(
                None,
                None,
                json_ld::syntax::Value::parse_str(context_str, |span| span)?,
            );

            Ok(context_document)
        }
        .boxed()
    }
}

/// Get JSON-LD context loader.
///
/// Optionally provide additional runtime contexts that take precedence over static contexts.
pub fn loader(additional_contexts: Option<HashMap<String, String>>) -> Result<ContextLoader> {
    let static_context_map = static_contexts()?;

    let loader = ContextLoader {
        static_context_map,
        additional_contexts: additional_contexts.unwrap_or_default(),
    };

    Ok(loader)
}

/// Get static contexts map.
///
/// These context are included in memory for commonly used JSON-LD contexts
/// to prevent frequent http and cid lookups during JSON-LD expansion.
pub fn static_contexts() -> Result<&'static ContextMap> {
    static STATIC_CONTEXTS: OnceCell<ContextMap> = OnceCell::new();

    let static_contexts = STATIC_CONTEXTS.get_or_try_init(build_static_contexts)?;

    Ok(static_contexts)
}

fn build_static_contexts() -> Result<ContextMap> {
    // TODO: clean this up so it can be defined cleaner
    // (non-trivial bit is generating the string in include_str since it's a macro)
    let urn_cid_links: ContextMap = [
        // latest
        (
            "urn:cid:bafkr4ibtc72t26blsnipjniwpoawtopufixoe7bbloqk7ko65cizgnhgnq".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ibtc72t26blsnipjniwpoawtopufixoe7bbloqk7ko65cizgnhgnq"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ihgnzvmiaoyfeil6p56pbznofd7d4gy5qxm75rxiiy6xty6zu4up4".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ihgnzvmiaoyfeil6p56pbznofd7d4gy5qxm75rxiiy6xty6zu4up4"
                );
                validate_json_string(json)?;
                json
            },
        ),
        // keep old contexts for backward compatability with statements generated with old sdk versions
        (
            "urn:cid:bafkr4ieddazlnl77lxwrygp5ky2sabfdpcowgrdr2nthd6hkhr2vcxciry".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ieddazlnl77lxwrygp5ky2sabfdpcowgrdr2nthd6hkhr2vcxciry"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iegfox4fmrwmjwyhnmc4rxegbzeosob5iom3tb6pejhzbekw4xk6y".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4iegfox4fmrwmjwyhnmc4rxegbzeosob5iom3tb6pejhzbekw4xk6y"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ib6mu2ldimhdotyqo3kocz5nhl5kbcvbhtll2lf57vmdjg6rg4tbu".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ib6mu2ldimhdotyqo3kocz5nhl5kbcvbhtll2lf57vmdjg6rg4tbu"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iavz5hgvy4uayvzvzle7gtsbn3u76pfhndzkvh3jefksqmltme56m".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4iavz5hgvy4uayvzvzle7gtsbn3u76pfhndzkvh3jefksqmltme56m"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iagb4u7jqlwqrftw4mn3l634wmgatmpvvzqgntgxaaerzljhggvdu".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4iagb4u7jqlwqrftw4mn3l634wmgatmpvvzqgntgxaaerzljhggvdu"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4icpymetiq3cic3yyeolnwqcgwc56dt6mrcbl6tkoaadfvwy2dhaue".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4icpymetiq3cic3yyeolnwqcgwc56dt6mrcbl6tkoaadfvwy2dhaue"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ifqh6sdsrgtos7kcukyoi4d3vsdrk3gwxuwgzs5d7pojrlzaecamy".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ifqh6sdsrgtos7kcukyoi4d3vsdrk3gwxuwgzs5d7pojrlzaecamy"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ib46vg45fimlp4shjfmh26t6uiny663obgmseircwt3bd2nqx34mu".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ib46vg45fimlp4shjfmh26t6uiny663obgmseircwt3bd2nqx34mu"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ibb27ow5o2yukccjjyrcunsk6jw4muacuk22cny7qdlw5wkfwxl2u".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ibb27ow5o2yukccjjyrcunsk6jw4muacuk22cny7qdlw5wkfwxl2u"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iep2pf2ha545wx44pzkutrfp2okwk4ks6fetcje77kbegomsb3qpy".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4iep2pf2ha545wx44pzkutrfp2okwk4ks6fetcje77kbegomsb3qpy"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ibcfbpprpgyqjyu2v4wddq66aeytknnlma2qd2gx3gelqhzkzc3pq".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ibcfbpprpgyqjyu2v4wddq66aeytknnlma2qd2gx3gelqhzkzc3pq"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4igip7ytxczqn27sokrcaeg7bcrny6xqpucrjthmeskmw6rj5fo63a".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4igip7ytxczqn27sokrcaeg7bcrny6xqpucrjthmeskmw6rj5fo63a"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4icpqn6xq6ekukybpd6bq4g2whdfjw7wnhigygrngcxdi423mlwafq".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4icpqn6xq6ekukybpd6bq4g2whdfjw7wnhigygrngcxdi423mlwafq"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4id5nmgxqdkosw4uvnrgqrqvczisyroglzxx4s7paaml3ngxlipbk4".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4id5nmgxqdkosw4uvnrgqrqvczisyroglzxx4s7paaml3ngxlipbk4"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iawq2vpvr64eopcgqfw3zgs3znpkmynlmyzbip7v3ip4mx2cqkxya".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4iawq2vpvr64eopcgqfw3zgs3znpkmynlmyzbip7v3ip4mx2cqkxya"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4icp6axdwtsb6hcio5r2unypijfuwlp66jqci2zr2hbcvqumbxkieu".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4icp6axdwtsb6hcio5r2unypijfuwlp66jqci2zr2hbcvqumbxkieu"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iavlckcavxdnqnn7kfwkvpxeffnclp5odzxv4sgwwiuvq3jofxwyi".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4iavlckcavxdnqnn7kfwkvpxeffnclp5odzxv4sgwwiuvq3jofxwyi"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ich3kfqujikgzf6op6olv7wd6rnxfhvjbxkunccpq3d226hchjbs4".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ich3kfqujikgzf6op6olv7wd6rnxfhvjbxkunccpq3d226hchjbs4"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iabnkikpzzyfflv7fjphyggja6uwwi3224u24pmmzmgyfsprdex4q".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4iabnkikpzzyfflv7fjphyggja6uwwi3224u24pmmzmgyfsprdex4q"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ihfxf47x5w7geqgsmjzcu3xpkxvidwqqj4jzersgb5nk4iu7vho7a".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ihfxf47x5w7geqgsmjzcu3xpkxvidwqqj4jzersgb5nk4iu7vho7a"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ihuzdhq2mma2z7352s47nfnjntprcqfsjas4wfb72bcl3tbw5goji".to_owned(),
            {
                let json = include_str!(
                    "../../static_contexts/cid/bafkr4ihuzdhq2mma2z7352s47nfnjntprcqfsjas4wfb72bcl3tbw5goji"
                );
                validate_json_string(json)?;
                json
            },
        ),
    ]
    .into_iter()
    .collect();

    let http_links: ContextMap = [
        ("https://www.w3.org/ns/did/v1", {
            let json = include_str!("../../static_contexts/http/www.w3.org/ns/did/v1");
            validate_json_string(json)?;
            json
        }),
        ("https://www.w3.org/2018/credentials/v1", {
            let json = include_str!("../../static_contexts/http/www.w3.org/2018/credentials/v1");
            validate_json_string(json)?;
            json
        }),
        ("https://www.w3.org/ns/credentials/v2", {
            let json = include_str!("../../static_contexts/http/www.w3.org/ns/credentials/v2");
            validate_json_string(json)?;
            json
        }),
        ("https://w3id.org/security/v1", {
            let json = include_str!("../../static_contexts/http/w3id.org/security/v1");
            validate_json_string(json)?;
            json
        }),
        ("https://w3id.org/security/v2", {
            let json = include_str!("../../static_contexts/http/w3id.org/security/v2");
            validate_json_string(json)?;
            json
        }),
    ]
    .into_iter()
    .map(|(link, json)| (link.to_owned(), json))
    .collect();

    let context_map = {
        let mut map = HashMap::new();

        map.extend(urn_cid_links);
        map.extend(http_links);

        map
    };

    Ok(context_map)
}

fn validate_json_string(s: &str) -> Result<()> {
    let _ = serde_json::from_str::<serde_json::Value>(s)?;

    Ok(())
}
