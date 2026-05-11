/// Hearth SDK error type.
#[derive(Debug, thiserror::Error)]
pub enum HearthError {
    #[error("HTTP {status}: {message}")]
    Api {
        status: u16,
        message: String,
        details: Option<serde_json::Value>,
    },

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}
