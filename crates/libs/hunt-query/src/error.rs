use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("NATS error: {0}")]
    Nats(String),
    #[error("JetStream error: {0}")]
    JetStream(String),
    #[error("envelope parse error: {0}")]
    EnvelopeParse(String),
    #[error("invalid time range: {0}")]
    InvalidTimeRange(String),
    #[error("invalid query: {0}")]
    InvalidQuery(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("regex error: {0}")]
    Regex(String),
}

pub type Result<T> = std::result::Result<T, Error>;
