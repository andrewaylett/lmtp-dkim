use crate::inbound::downstream::DownstreamClient;
use email_primitives::Message;
use lmtp::session::{Envelope, MessageHandler, RecipientResult};
use std::sync::Arc as StdArc;

/// LMTP [`MessageHandler`] for the inbound pipeline.
#[derive(Clone)]
#[expect(dead_code, reason = "stub: constructed in run() once implemented")]
pub(crate) struct InboundHandler {
    inner: StdArc<InboundHandlerInner>,
}

#[expect(
    dead_code,
    reason = "stub: fields used by MessageHandler::handle once implemented"
)]
struct InboundHandlerInner {
    arc_signer: arc::ArcSigner,
    dkim_verifier: dkim::Verifier,
    arc_validator: arc::ChainValidator,
    downstream: DownstreamClient,
    authserv_id: String,
}

impl MessageHandler for InboundHandler {
    async fn handle(
        &self,
        envelope: Envelope,
        message: Message,
    ) -> lmtp::Result<Vec<RecipientResult>> {
        let _ = (envelope, message);
        todo!(
            "1. dkim_verifier.verify(&message); \
             2. arc_validator.validate(&message); \
             3. evaluate SPF (envelope.sender, client IP from LHLO domain); \
             4. build SealRequest with auth results; \
             5. arc_signer.seal(&message, chain_result, seal_request); \
             6. downstream.deliver(envelope, sealed_message); \
             7. map downstream per-recipient replies to RecipientResult"
        )
    }
}
