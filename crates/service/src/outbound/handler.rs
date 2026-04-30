use crate::outbound::downstream::DownstreamClient;
use email_primitives::Message;
use lmtp::session::{Envelope, MessageHandler, RecipientResult};
use std::collections::HashMap;
use std::sync::Arc as StdArc;

/// LMTP [`MessageHandler`] for the outbound pipeline.
#[derive(Clone)]
#[expect(dead_code, reason = "stub: constructed in run() once implemented")]
pub(crate) struct OutboundHandler {
    inner: StdArc<OutboundHandlerInner>,
}

#[expect(
    dead_code,
    reason = "stub: fields used by MessageHandler::handle once implemented"
)]
struct OutboundHandlerInner {
    /// Map from lowercase domain string to configured signer.
    ///
    /// Keyed by the `d=` domain as configured in `[[dkim]]`.
    signers: HashMap<String, dkim::Signer>,
    downstream: DownstreamClient,
}

impl MessageHandler for OutboundHandler {
    async fn handle(
        &self,
        envelope: Envelope,
        message: Message,
    ) -> lmtp::Result<Vec<RecipientResult>> {
        let _ = (envelope, message);
        todo!(
            "1. extract From: header domain; \
             2. look up self.inner.signers.get(domain); \
             3. if found: signer.sign(&message); \
             4. if not found: warn and use unsigned message; \
             5. downstream.deliver(envelope, signed_or_original_message); \
             6. return per-recipient RecipientResult"
        )
    }
}
