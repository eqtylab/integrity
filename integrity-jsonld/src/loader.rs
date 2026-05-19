use std::collections::HashMap;

use anyhow::Result;
use once_cell::sync::OnceCell;
use ssi_json_ld::ContextLoader;

type ContextMap = HashMap<String, &'static str>;

/// Get JSON-LD context loader, pre-loaded with our static contexts plus the
/// W3C contexts ssi already ships with.
///
/// Optionally provide additional runtime contexts that take precedence over
/// static contexts.
pub fn loader(additional_contexts: Option<HashMap<String, String>>) -> Result<ContextLoader> {
    let static_context_map = static_contexts()?;

    let mut combined: HashMap<String, String> = static_context_map
        .iter()
        .map(|(k, v)| (k.clone(), (*v).to_string()))
        .collect();
    if let Some(additional) = additional_contexts {
        combined.extend(additional);
    }

    let loader = ContextLoader::default()
        .with_static_loader()
        .with_context_map_from(combined)
        .map_err(|e| anyhow::anyhow!("failed to build context loader: {e}"))?;

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
            "urn:cid:bafkr4icploa577ziqnb57jlpoj7l2hi5kgt3knxpdtunlttjd3q33zeqpy".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4icploa577ziqnb57jlpoj7l2hi5kgt3knxpdtunlttjd3q33zeqpy"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ic7ydwk3rtoltyzx4zn3vvu3r7hpzxtmbzmnksotx7k5nbnwclf6m".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ic7ydwk3rtoltyzx4zn3vvu3r7hpzxtmbzmnksotx7k5nbnwclf6m"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ibtc72t26blsnipjniwpoawtopufixoe7bbloqk7ko65cizgnhgnq".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ibtc72t26blsnipjniwpoawtopufixoe7bbloqk7ko65cizgnhgnq"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ihgnzvmiaoyfeil6p56pbznofd7d4gy5qxm75rxiiy6xty6zu4up4".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ihgnzvmiaoyfeil6p56pbznofd7d4gy5qxm75rxiiy6xty6zu4up4"
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
                    "../static_contexts/cid/bafkr4ieddazlnl77lxwrygp5ky2sabfdpcowgrdr2nthd6hkhr2vcxciry"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iegfox4fmrwmjwyhnmc4rxegbzeosob5iom3tb6pejhzbekw4xk6y".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4iegfox4fmrwmjwyhnmc4rxegbzeosob5iom3tb6pejhzbekw4xk6y"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ib6mu2ldimhdotyqo3kocz5nhl5kbcvbhtll2lf57vmdjg6rg4tbu".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ib6mu2ldimhdotyqo3kocz5nhl5kbcvbhtll2lf57vmdjg6rg4tbu"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iavz5hgvy4uayvzvzle7gtsbn3u76pfhndzkvh3jefksqmltme56m".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4iavz5hgvy4uayvzvzle7gtsbn3u76pfhndzkvh3jefksqmltme56m"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iagb4u7jqlwqrftw4mn3l634wmgatmpvvzqgntgxaaerzljhggvdu".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4iagb4u7jqlwqrftw4mn3l634wmgatmpvvzqgntgxaaerzljhggvdu"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4icpymetiq3cic3yyeolnwqcgwc56dt6mrcbl6tkoaadfvwy2dhaue".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4icpymetiq3cic3yyeolnwqcgwc56dt6mrcbl6tkoaadfvwy2dhaue"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ifqh6sdsrgtos7kcukyoi4d3vsdrk3gwxuwgzs5d7pojrlzaecamy".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ifqh6sdsrgtos7kcukyoi4d3vsdrk3gwxuwgzs5d7pojrlzaecamy"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ib46vg45fimlp4shjfmh26t6uiny663obgmseircwt3bd2nqx34mu".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ib46vg45fimlp4shjfmh26t6uiny663obgmseircwt3bd2nqx34mu"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ibb27ow5o2yukccjjyrcunsk6jw4muacuk22cny7qdlw5wkfwxl2u".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ibb27ow5o2yukccjjyrcunsk6jw4muacuk22cny7qdlw5wkfwxl2u"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iep2pf2ha545wx44pzkutrfp2okwk4ks6fetcje77kbegomsb3qpy".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4iep2pf2ha545wx44pzkutrfp2okwk4ks6fetcje77kbegomsb3qpy"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ibcfbpprpgyqjyu2v4wddq66aeytknnlma2qd2gx3gelqhzkzc3pq".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ibcfbpprpgyqjyu2v4wddq66aeytknnlma2qd2gx3gelqhzkzc3pq"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4igip7ytxczqn27sokrcaeg7bcrny6xqpucrjthmeskmw6rj5fo63a".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4igip7ytxczqn27sokrcaeg7bcrny6xqpucrjthmeskmw6rj5fo63a"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4icpqn6xq6ekukybpd6bq4g2whdfjw7wnhigygrngcxdi423mlwafq".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4icpqn6xq6ekukybpd6bq4g2whdfjw7wnhigygrngcxdi423mlwafq"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4id5nmgxqdkosw4uvnrgqrqvczisyroglzxx4s7paaml3ngxlipbk4".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4id5nmgxqdkosw4uvnrgqrqvczisyroglzxx4s7paaml3ngxlipbk4"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iawq2vpvr64eopcgqfw3zgs3znpkmynlmyzbip7v3ip4mx2cqkxya".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4iawq2vpvr64eopcgqfw3zgs3znpkmynlmyzbip7v3ip4mx2cqkxya"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4icp6axdwtsb6hcio5r2unypijfuwlp66jqci2zr2hbcvqumbxkieu".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4icp6axdwtsb6hcio5r2unypijfuwlp66jqci2zr2hbcvqumbxkieu"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iavlckcavxdnqnn7kfwkvpxeffnclp5odzxv4sgwwiuvq3jofxwyi".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4iavlckcavxdnqnn7kfwkvpxeffnclp5odzxv4sgwwiuvq3jofxwyi"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ich3kfqujikgzf6op6olv7wd6rnxfhvjbxkunccpq3d226hchjbs4".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ich3kfqujikgzf6op6olv7wd6rnxfhvjbxkunccpq3d226hchjbs4"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4iabnkikpzzyfflv7fjphyggja6uwwi3224u24pmmzmgyfsprdex4q".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4iabnkikpzzyfflv7fjphyggja6uwwi3224u24pmmzmgyfsprdex4q"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ihfxf47x5w7geqgsmjzcu3xpkxvidwqqj4jzersgb5nk4iu7vho7a".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ihfxf47x5w7geqgsmjzcu3xpkxvidwqqj4jzersgb5nk4iu7vho7a"
                );
                validate_json_string(json)?;
                json
            },
        ),
        (
            "urn:cid:bafkr4ihuzdhq2mma2z7352s47nfnjntprcqfsjas4wfb72bcl3tbw5goji".to_owned(),
            {
                let json = include_str!(
                    "../static_contexts/cid/bafkr4ihuzdhq2mma2z7352s47nfnjntprcqfsjas4wfb72bcl3tbw5goji"
                );
                validate_json_string(json)?;
                json
            },
        ),
    ]
    .into_iter()
    .collect();

    // The W3C/security contexts the old code shipped are now provided by
    // ssi_json_ld's built-in StaticLoader (CREDENTIALS_V1, CREDENTIALS_V2,
    // SECURITY_V1, SECURITY_V2, DID_V1, ...). No need to re-add them here.
    Ok(urn_cid_links)
}

fn validate_json_string(s: &str) -> Result<()> {
    let _ = serde_json::from_str::<serde_json::Value>(s)?;

    Ok(())
}
