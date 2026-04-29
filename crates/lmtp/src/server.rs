//! LMTP server listener.
//!
//! The [`Server`] binds to a TCP address or a Unix domain socket and spawns a
//! tokio task per connection. Each task runs a [`crate::Session`] to completion.
//!
//! # Connection flow per client
//!
//! ```text
//! accept() ─▶ send 220 greeting ─▶ loop {
//!     read command line (CommandCodec)
//!     ──▶ session.handle_command()
//!     ──▶ send reply
//!     if DATA command:
//!         send 354
//!         switch to DataCodec
//!         read body
//!         switch back to CommandCodec
//!         session.receive_data() ─▶ returns Vec<Reply>
//!         send each reply in order
//!     if QUIT:
//!         break
//! }
//! close connection
//! ```
//!
//! # Shutdown
//!
//! The server respects tokio's cancellation model. Pass a [`tokio::sync::watch`]
//! receiver (or a [`tokio_util::sync::CancellationToken`]) to trigger graceful
//! shutdown: stop accepting new connections, let in-flight sessions drain.

use std::sync::Arc;

use tokio::net::{TcpListener, UnixListener};
use tracing::{error, info};

use crate::session::MessageHandler;
use crate::Result;

/// Configuration for the LMTP server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The hostname to announce in the `220` greeting and `221` closing.
    pub hostname: String,

    /// Maximum accepted message size in bytes (enforced in [`crate::codec::DataCodec`]).
    ///
    /// Advertised via the `SIZE` extension in `LHLO` responses (RFC 1870).
    pub max_message_size: usize,

    /// ESMTP extensions to advertise in `LHLO`. Currently defined values:
    /// - `"8BITMIME"` – RFC 6152
    /// - `"ENHANCEDSTATUSCODES"` – RFC 2034
    /// - `"SIZE <n>"` – RFC 1870 (automatically added from `max_message_size`)
    pub extensions: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            hostname: "localhost".to_owned(),
            max_message_size: crate::codec::DEFAULT_MAX_MESSAGE_SIZE,
            extensions: vec!["8BITMIME".to_owned(), "ENHANCEDSTATUSCODES".to_owned()],
        }
    }
}

/// An LMTP server that accepts connections and dispatches to a [`MessageHandler`].
///
/// The `H` type is cloned (or Arc'd) for each accepted connection so that
/// connections can run concurrently.
pub struct Server<H: MessageHandler + Clone + 'static> {
    config: ServerConfig,
    handler: H,
}

impl<H: MessageHandler + Clone + 'static> Server<H> {
    /// Construct a new server with the given configuration and message handler.
    pub fn new(config: ServerConfig, handler: H) -> Self {
        Self { config, handler }
    }

    /// Bind to a TCP socket and serve connections until the process exits.
    ///
    /// Each accepted connection is handled in a dedicated tokio task.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP bind fails.
    pub async fn serve_tcp(self, listener: TcpListener) -> Result<()> {
        let config = Arc::new(self.config);
        info!(addr = ?listener.local_addr()?, "LMTP server listening (TCP)");
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let config = Arc::clone(&config);
            let handler = self.handler.clone();
            tokio::spawn(async move {
                info!(%peer_addr, "accepted connection");
                if let Err(e) = Self::run_session(config, handler, stream).await {
                    error!(%peer_addr, error = %e, "session error");
                }
            });
        }
    }

    /// Bind to a Unix domain socket and serve connections.
    pub async fn serve_unix(self, listener: UnixListener) -> Result<()> {
        let config = Arc::new(self.config);
        info!("LMTP server listening (Unix socket)");
        loop {
            let (stream, _) = listener.accept().await?;
            let config = Arc::clone(&config);
            let handler = self.handler.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::run_session(config, handler, stream).await {
                    error!(error = %e, "session error");
                }
            });
        }
    }

    /// Drive a single LMTP session to completion over an async stream.
    ///
    /// `S` must implement both `AsyncRead` and `AsyncWrite` (satisfied by
    /// `TcpStream` and `UnixStream`).
    async fn run_session<S>(_config: Arc<ServerConfig>, _handler: H, _stream: S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        todo!(
            "wrap stream in Framed<CommandCodec>; send greeting; \
             loop: decode command, call session.handle_command(), send reply; \
             on DATA: switch to DataCodec, decode body, call session.receive_data(), \
             send per-recipient replies, switch back to CommandCodec; \
             on QUIT: send 221 and return Ok(())"
        )
    }
}
