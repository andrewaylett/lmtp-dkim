use email_primitives::Message;
use lmtp::session::{Envelope, RecipientResult};

/// Client for forwarding messages to the downstream LMTP server.
///
/// Initiates an LMTP session (sends LHLO, MAIL FROM, RCPT TO ×N, DATA)
/// and collects per-recipient responses.
pub(crate) struct DownstreamClient {
    // connection pool or address config
}

impl DownstreamClient {
    /// Forward a message to the downstream LMTP server.
    ///
    /// Returns one [`RecipientResult`] per entry in `envelope.recipients`,
    /// suitable for passing back to the upstream client.
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
             send LHLO; MAIL FROM; RCPT TO * recipients; DATA; \
             collect per-recipient 250/4xx/5xx replies; close or cache connection"
        )
    }
}
