use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    Analysis,
    Compat,
}

impl RuntimeMode {
    pub const ENV: &'static str = "COMPATRA_MODE";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Analysis => "analysis",
            Self::Compat => "compat",
        }
    }

    pub fn is_analysis(self) -> bool {
        matches!(self, Self::Analysis)
    }

    pub fn is_compat(self) -> bool {
        matches!(self, Self::Compat)
    }

    pub fn from_env() -> Result<Self, String> {
        match std::env::var(Self::ENV) {
            Ok(raw) => raw.parse(),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(err) => Err(format!("{} is not readable: {}", Self::ENV, err)),
        }
    }
}

impl Default for RuntimeMode {
    fn default() -> Self {
        Self::Analysis
    }
}

impl fmt::Display for RuntimeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RuntimeMode {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "analysis" | "analyze" | "malware" => Ok(Self::Analysis),
            "compat" | "compatibility" | "run" => Ok(Self::Compat),
            other => Err(format!(
                "unsupported runtime mode '{}'; expected 'analysis' or 'compat'",
                other
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_analysis_and_compat_aliases() {
        assert_eq!("analysis".parse::<RuntimeMode>(), Ok(RuntimeMode::Analysis));
        assert_eq!(
            "compatibility".parse::<RuntimeMode>(),
            Ok(RuntimeMode::Compat)
        );
        assert_eq!("run".parse::<RuntimeMode>(), Ok(RuntimeMode::Compat));
    }
}
