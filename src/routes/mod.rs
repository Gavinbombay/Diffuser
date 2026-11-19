//! HTTP handlers grouped by native, compatibility and lifecycle responsibilities.
mod common;
pub(crate) use common::*;
mod pull;
pub(crate) use pull::*;
mod compat;
pub(crate) use compat::*;
mod jobs;
pub(crate) use jobs::*;
mod queue;
pub(crate) use queue::*;
mod server;
pub(crate) use server::*;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn mod_body_size_and_content_type_refusals() {
        crate::routes::common::check_request_refusals(&[
            "/v1/agent/pull",
            "/v1/generate",
            "/v1/chat/completions",
            "/openai/v1/chat/completions",
            "/v1/embeddings",
            "/openai/v1/embeddings",
            "/v1/embed",
            "/embed",
            "/v1/lanes/tts/jobs",
            "/v1/lanes/tts/jobs/fixture/cancel",
        ])
        .await;
    }
}

#[cfg(test)]
mod input_hardening_tests {
    #[tokio::test]
    async fn mod_body_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/health", "GET")],
            &["/v1/lanes/%FF/workers"],
            "body",
        )
        .await;
    }
    #[tokio::test]
    async fn mod_path_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/health", "GET")],
            &["/v1/lanes/%FF/workers"],
            "path",
        )
        .await;
    }
    #[tokio::test]
    async fn mod_fields_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/health", "GET")],
            &["/v1/lanes/%FF/workers"],
            "fields",
        )
        .await;
    }
}
