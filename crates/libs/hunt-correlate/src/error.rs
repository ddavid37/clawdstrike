use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("YAML parse error: {0}")]
    Yaml(String),
    #[error("invalid rule: {0}")]
    InvalidRule(String),
    #[error("correlation engine error: {0}")]
    EngineError(String),
    #[error("watch error: {0}")]
    WatchError(String),
    #[error("NATS error: {0}")]
    Nats(String),
    #[error("IOC parse error: {0}")]
    IocParse(String),
    #[error("IOC match error: {0}")]
    IocMatch(String),
    #[error("report generation error: {0}")]
    ReportError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("regex error: {0}")]
    Regex(String),
}

pub type Result<T> = std::result::Result<T, Error>;
