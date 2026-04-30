use email_primitives::Message;
use lmtp::session::{Envelope, RecipientResult};

/// Client for forwarding signed messages downstream.
///
/// Identical in structure to the inbound [`crate::inbound::DownstreamClient`];
/// consider extracting to a shared module once both modes are implemented.
pub(crate) struct DownstreamClient {
    // connection pool or address config
}

impl DownstreamClient {
    #[expect(
        dead_code,
        reason = "stub: called by MessageHandler::handle once implemented"
    )]
    #[expect(
        clippy::unused_async,
        reason = "stub: will await LMTP connection once implemented"
    )]
    async fn deliver(
        &self,
        _envelope: &Envelope,
        _message: &Message,
    ) -> lmtp::Result<Vec<RecipientResult>> {
        todo!(
            "open TCP/Unix connection to downstream; \
             LHLO, MAIL FROM, RCPT TO, DATA; \
             collect per-recipient replies"
        )
    }
}
