use machina_mode::RuntimeMode;

use crate::AnalysisServices;

pub const TRACE_FN_ENTRY_ENV: &str = "MACHINA_TRACE_FN_ENTRY";
pub const BYPASS_USAGE_CHECK_ENV: &str = "MACHINA_BYPASS_USAGE_CHECK";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionEntryProbeSpec {
    pub label: String,
    pub addr: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageBypassHookSpec {
    pub addr: u64,
    pub lr_filter: Option<u64>,
    pub values: Vec<u64>,
}

pub fn function_entry_specs_from_env(mode: RuntimeMode) -> Vec<FunctionEntryProbeSpec> {
    if AnalysisServices::for_mode(mode).is_none() {
        return Vec::new();
    }
    std::env::var(TRACE_FN_ENTRY_ENV)
        .ok()
        .map(|spec| parse_function_entry_specs(&spec))
        .unwrap_or_default()
}

pub fn usage_bypass_specs_from_env(mode: RuntimeMode) -> Vec<UsageBypassHookSpec> {
    if AnalysisServices::for_mode(mode).is_none() {
        return Vec::new();
    }
    std::env::var(BYPASS_USAGE_CHECK_ENV)
        .ok()
        .map(|spec| parse_usage_bypass_specs(&spec))
        .unwrap_or_default()
}

pub fn parse_function_entry_specs(spec: &str) -> Vec<FunctionEntryProbeSpec> {
    spec.split(',')
        .filter_map(|entry| {
            let (label, addr_str) = entry.trim().split_once(':')?;
            parse_hex_u64(addr_str).map(|addr| FunctionEntryProbeSpec {
                label: label.to_string(),
                addr,
            })
        })
        .collect()
}

pub fn parse_usage_bypass_specs(spec: &str) -> Vec<UsageBypassHookSpec> {
    let tokens: Vec<&str> = if spec.contains(';') {
        spec.split(';').collect()
    } else if spec.split(',').all(|token| !token.contains('=')) {
        spec.split(',').collect()
    } else {
        vec![spec]
    };

    tokens
        .into_iter()
        .filter_map(|token| {
            let token = token.trim();
            if token.is_empty() {
                return None;
            }
            let (addr_str, values_str) = token.split_once('=').unwrap_or((token, "0"));
            let (addr_str, lr_filter) = match addr_str.split_once('@') {
                Some((addr, lr)) => (addr, Some(parse_hex_u64(lr)?)),
                None => (addr_str, None),
            };
            let addr = parse_hex_u64(addr_str)?;
            let values = values_str.split(',').map(parse_u64_token).collect();
            Some(UsageBypassHookSpec {
                addr,
                lr_filter,
                values,
            })
        })
        .collect()
}

fn parse_hex_u64(value: &str) -> Option<u64> {
    let stripped = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    u64::from_str_radix(stripped, 16).ok()
}

fn parse_u64_token(value: &str) -> u64 {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        value.parse::<u64>().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_function_entry_specs() {
        assert_eq!(
            parse_function_entry_specs("main:0x1000,helper:2000"),
            vec![
                FunctionEntryProbeSpec {
                    label: "main".to_string(),
                    addr: 0x1000,
                },
                FunctionEntryProbeSpec {
                    label: "helper".to_string(),
                    addr: 0x2000,
                }
            ]
        );
    }

    #[test]
    fn parses_usage_bypass_specs_with_filters_and_value_sequences() {
        assert_eq!(
            parse_usage_bypass_specs("0x1000@0x2000=0,1;0x3000=0x2"),
            vec![
                UsageBypassHookSpec {
                    addr: 0x1000,
                    lr_filter: Some(0x2000),
                    values: vec![0, 1],
                },
                UsageBypassHookSpec {
                    addr: 0x3000,
                    lr_filter: None,
                    values: vec![2],
                }
            ]
        );
    }

    #[test]
    fn keeps_legacy_comma_address_form() {
        assert_eq!(
            parse_usage_bypass_specs("0x1000,0x2000"),
            vec![
                UsageBypassHookSpec {
                    addr: 0x1000,
                    lr_filter: None,
                    values: vec![0],
                },
                UsageBypassHookSpec {
                    addr: 0x2000,
                    lr_filter: None,
                    values: vec![0],
                }
            ]
        );
    }
}
