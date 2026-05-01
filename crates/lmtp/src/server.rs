//! LMTP server listener.
//!
//! The [`Server`] binds to a TCP address or a Unix domain socket and spawns a
//! tokio task per connection. Each task runs a [`Session`] to completion.
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
//!         send 221 and return
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

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, UnixListener};
use tokio_util::codec::{Framed, FramedParts};
use tracing::{error, info, warn};

use crate::codec::{CommandCodec, DataCodec};
use crate::command::Command;
use crate::response::ReplyCode;
use crate::session::{MessageHandler, Session};
use crate::{Error, Reply, Result};

trait ReadWriteStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {}
impl<S> ReadWriteStream for S where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
}

/// Configuration for the LMTP server.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The hostname to announce in the `220` greeting and `221` closing.
    pub hostname: String,

    /// Maximum accepted message size in bytes (enforced in [`DataCodec`]).
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
pub struct Server<H: MessageHandler> {
    config: ServerConfig,
    handler: H,
}

impl<H: MessageHandler> Server<H> {
    /// Construct a new server with the given configuration and message handler.
    #[must_use]
    pub const fn new(config: ServerConfig, handler: H) -> Self {
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
    ///
    /// # Errors
    ///
    /// Returns an error if the Unix socket `accept` call fails.
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
    async fn run_session<S: ReadWriteStream>(
        config: Arc<ServerConfig>,
        handler: H,
        stream: S,
    ) -> Result<()> {
        let mut session = Session::new(&config.hostname, handler);
        let mut framed = Framed::new(stream, CommandCodec::new());

        // RFC 2033 §4: server sends 220 greeting immediately after connection.
        framed.send(session.greeting()).await?;

        loop {
            if let Some(frame) = framed.next().await {
                let line = frame?;

                let cmd = match Command::parse(&line) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e, "bad command from client");
                        framed.send(Reply::syntax_error()).await?;
                        continue;
                    }
                };

                let is_data = matches!(cmd, Command::Data);

                let reply = match session.handle_command(cmd).await {
                    Ok(r) => r,
                    Err(Error::OutOfSequence(msg)) => {
                        warn!("out of sequence: {msg}");
                        framed.send(Reply::bad_sequence()).await?;
                        continue;
                    }
                    Err(e) => return Err(e),
                };

                let done = reply.code == ReplyCode::SERVICE_CLOSING;
                framed.send(reply).await?;
                if done {
                    return Ok(());
                }

                if is_data {
                    framed = Self::receive_body(framed, &mut session, &config).await?;
                }
            } else {
                return Ok(());
            }
        }
    }

    /// Switch to [`DataCodec`], read the message body, call [`Session::receive_data`],
    /// send per-recipient replies, then switch back to [`CommandCodec`].
    async fn receive_body<S: ReadWriteStream>(
        framed: Framed<S, CommandCodec>,
        session: &mut Session<H>,
        config: &ServerConfig,
    ) -> Result<Framed<S, CommandCodec>> {
        // Carry over buffered bytes so no data is lost between codec switches.
        let FramedParts {
            io,
            read_buf,
            write_buf,
            ..
        } = framed.into_parts();
        let mut data_parts = FramedParts::new(io, DataCodec::new(config.max_message_size));
        data_parts.read_buf = read_buf;
        data_parts.write_buf = write_buf;
        let mut data_framed = Framed::from_parts(data_parts);

        let raw = match data_framed.next().await {
            None => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "client closed connection during DATA",
                )));
            }
            Some(Err(e)) => return Err(e),
            Some(Ok(b)) => b,
        };

        let replies = session.receive_data(raw).await?;

        // Switch back to CommandCodec, carrying over any buffered bytes.
        let FramedParts {
            io,
            read_buf,
            write_buf,
            ..
        } = data_framed.into_parts();
        let mut cmd_parts = FramedParts::new::<Reply>(io, CommandCodec::new());
        cmd_parts.read_buf = read_buf;
        cmd_parts.write_buf = write_buf;
        let mut cmd_framed = Framed::from_parts(cmd_parts);

        for reply in replies {
            cmd_framed.send(reply).await?;
        }

        Ok(cmd_framed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::{Server, ServerConfig};
    use crate::session::{Envelope, MessageHandler, RecipientResult};
    use crate::{Reply, Result};
    use email_primitives::Message;

    #[derive(Clone)]
    struct OkHandler;

    impl MessageHandler for OkHandler {
        async fn handle(
            &self,
            envelope: Envelope,
            _message: Message,
        ) -> Result<Vec<RecipientResult>> {
            Ok(envelope
                .recipients
                .into_iter()
                .map(|recipient| RecipientResult {
                    recipient,
                    reply: Reply::ok(),
                })
                .collect())
        }
    }

    /// Run a canned client script against a single session and return server output.
    ///
    /// Writes all `script` bytes upfront (they fit in the duplex buffer), runs
    /// the session to completion, then returns everything the server wrote.
    async fn run(script: &[u8]) -> String {
        let (mut client, server) = duplex(65536);
        let config = Arc::new(ServerConfig::default());
        client
            .write_all(script)
            .await
            .expect("write script to duplex");
        // Drop write half by calling shutdown; the server sees EOF after QUIT.
        client.shutdown().await.expect("shutdown write");
        Server::<OkHandler>::run_session(config, OkHandler, server)
            .await
            .expect("session ok");
        let mut output = String::new();
        client
            .read_to_string(&mut output)
            .await
            .expect("read server output");
        output
    }

    /// RFC 2033 §4: server sends 220 greeting on connect.
    #[tokio::test]
    async fn greeting_sent() {
        let out = run(b"QUIT\r\n").await;
        assert!(
            out.starts_with("220 "),
            "expected 220 greeting, got: {out:?}"
        );
    }

    /// LHLO is accepted with 250.
    #[tokio::test]
    async fn lhlo_accepted() {
        let out = run(b"LHLO client.example.com\r\nQUIT\r\n").await;
        assert!(out.contains("250 "), "expected 250 for LHLO, got: {out:?}");
    }

    /// QUIT sends 221 and ends the session.
    #[tokio::test]
    async fn quit_closes() {
        let out = run(b"QUIT\r\n").await;
        assert!(out.contains("221 "), "expected 221 for QUIT, got: {out:?}");
    }

    /// Unknown verb gets 500, then QUIT still works (RFC 5321 §4.2.5).
    #[tokio::test]
    async fn syntax_error_recovery() {
        let out = run(b"GARBAGE here\r\nQUIT\r\n").await;
        assert!(
            out.contains("500 "),
            "expected 500 for bad verb, got: {out:?}"
        );
        assert!(
            out.contains("221 "),
            "expected 221 after recovery, got: {out:?}"
        );
    }

    /// Full DATA transfer: LHLO → MAIL → RCPT → DATA → body → 250 per recipient.
    #[tokio::test]
    async fn full_data_transfer() {
        let script = b"LHLO client.example.com\r\n\
                       MAIL FROM:<sender@example.com>\r\n\
                       RCPT TO:<rcpt@example.com>\r\n\
                       DATA\r\n\
                       Subject: test\r\n\
                       \r\n\
                       body text\r\n\
                       .\r\n\
                       QUIT\r\n";
        let out = run(script).await;
        assert!(
            out.contains("354 "),
            "expected 354 start-data, got: {out:?}"
        );
        assert!(
            out.matches("250 ").count() >= 2,
            "expected ≥2 250 replies (LHLO+MAIL+RCPT+DATA), got: {out:?}"
        );
        assert!(out.contains("221 "), "expected 221 for QUIT, got: {out:?}");
    }
}
