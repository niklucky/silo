use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use silo_core::sync::{ErrorBody, ErrorCode, ErrorReply};

/// An error answered to the client as [`ErrorReply`]. Internal details are
/// logged, never sent.
#[derive(Debug)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Invalid, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(
            ErrorCode::Unauthorized,
            "missing, unknown or revoked device token",
        )
    }

    pub fn internal(detail: impl std::fmt::Display) -> Self {
        eprintln!("internal error: {detail}");
        Self::new(ErrorCode::Internal, "internal server error")
    }

    fn status(&self) -> StatusCode {
        match self.code {
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden | ErrorCode::InviteInvalid => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Invalid => StatusCode::BAD_REQUEST,
            ErrorCode::UsernameTaken | ErrorCode::IdentityTaken => StatusCode::CONFLICT,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(err: rusqlite::Error) -> Self {
        Self::internal(format!("sqlite: {err}"))
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        Self::internal(format!("stored json: {err}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ErrorReply {
            error: ErrorBody {
                code: self.code,
                message: self.message,
            },
        };
        (status, Json(body)).into_response()
    }
}
