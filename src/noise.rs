// =============================================================================
// primus-net-opt/src/noise.rs
//
// Noise_XX_25519_ChaChaPoly_SHA256 handshake with ML-DSA-87 identity binding.
//
// HANDSHAKE PROTOCOL:
//   Standard Noise XX pattern with an additional identity-binding step:
//   each party signs the other's ephemeral Noise key with their ML-DSA-87
//   signing key and includes the signature in the handshake payload alongside
//   their Node Record (PrimusNR). This prevents identity misbinding attacks
//   where a MITM substitutes their own Noise static key.
//
//   Message flow:
//     1. -> e                                        (initiator ephemeral)
//     2. <- e, ee, s, es + NR_resp + Sig_resp(e_i)  (responder identity)
//     3. -> s, se         + NR_init + Sig_init(e_r)  (initiator identity)
//
// DEPENDENCY NOTE:
//   This file uses ml-dsa directly for signing (SigningKey). Verification of
//   peer Node Records is delegated to PrimusNR::verify() (peer.rs, local to
//   this crate). The direct ml-dsa usage here is correct because
//   ephemeral-key signing is a local operation — we hold the signing key.
//
// FRAME FORMAT (wire):
//   [u16 BE length] [payload bytes]
//   WASM variant adds 6 bytes of zero-padding after the length field
//   for WebTransport framing compatibility:
//   [u16 BE length] [6 zero bytes] [payload bytes]
// =============================================================================

use anyhow::{Context as AnyhowContext, Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use ml_dsa::signature::{SignatureEncoding, Signer, Verifier};
use ml_dsa::{MlDsa87, SigningKey, VerifyingKey};
use crate::peer::PrimusNR;
use serde::{Deserialize, Serialize};
use snow::Builder;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

/// Handshake payload embedded in Noise messages 2 and 3: the sender's
/// self-signed Node Record plus a signature binding it to the peer's
/// ephemeral Noise key. This is what prevents identity-misbinding attacks
/// (see module header). Local to this crate now — previously came from
/// primus-types.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NoiseHandshakePayload {
    nr: PrimusNR,
    ephemeral_sig: Vec<u8>,
}

/// Noise pattern. Frozen — changing this breaks all existing peers.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Maximum plaintext payload per Noise transport message.
/// Noise imposes a 65535-byte limit per message including the AEAD tag.
pub const MAX_FRAME_SIZE: usize = 65535;

/// ChaCha20-Poly1305 AEAD tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Maximum plaintext bytes per `poll_write` call.
/// Enforced in `poll_write` to guarantee the encrypted frame fits in one
/// Noise message: `plaintext + TAG_LEN <= MAX_FRAME_SIZE`.
const MAX_PLAINTEXT: usize = MAX_FRAME_SIZE - TAG_LEN;

// ── BiStream ──────────────────────────────────────────────────────────────────

/// Combines a separate reader and writer into a single `AsyncRead + AsyncWrite`.
///
/// Combines a separate reader and writer into a single `AsyncRead + AsyncWrite`.
///
/// Used to wrap QUIC send/recv streams (which are separate objects) into the
/// unified `S: AsyncRead + AsyncWrite` that `NoiseStream` requires.
pub struct BiStream<R, W> {
    pub reader: R,
    pub writer: W,
}

impl<R, W> AsyncRead for BiStream<R, W>
where
    R: AsyncRead + Unpin,
    W: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R, W> AsyncWrite for BiStream<R, W>
where
    W: AsyncWrite + Unpin,
    R: Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

// ── NoiseStream ───────────────────────────────────────────────────────────────

/// An `AsyncRead + AsyncWrite` stream encrypted with Noise stateless transport.
///
/// After a successful handshake (`handshake_initiator` / `handshake_responder`),
/// all reads and writes are transparently encrypted/decrypted using the
/// negotiated ChaCha20-Poly1305 keys.
///
/// # Nonce handling
///
/// Uses separate monotonically increasing nonces for reading (`read_nonce`)
/// and writing (`write_nonce`). The stateless transport mode is used so that
/// nonces are managed explicitly here rather than inside snow, which allows
/// future nonce-rekey support without replacing the snow state machine.
///
/// # WASM padding
///
/// When `is_wasm = true`, the frame format gains 6 zero-bytes after the u16
/// length field to satisfy WebTransport's minimum-frame-size requirement.
/// Set this flag after handshake based on the transport type.
pub struct NoiseStream<S> {
    inner: S,
    pub noise: snow::StatelessTransportState,
    read_nonce: u64,
    write_nonce: u64,
    read_buf: BytesMut,
    decrypt_buf: BytesMut,
    write_buf: BytesMut,
    write_consumed: usize,
    pub is_wasm: bool,
}

impl<S> NoiseStream<S> {
    /// Destructure the stream into its raw inner transport and Noise state.
    ///
    /// Used when a higher-level protocol needs direct access to the Noise
    /// state (e.g., for rekeying or exporting session keys for audit).
    pub fn into_parts(self) -> (S, snow::StatelessTransportState) {
        (self.inner, self.noise)
    }
}

impl<S> NoiseStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(inner: S, noise: snow::StatelessTransportState) -> Self {
        Self {
            inner,
            noise,
            read_nonce: 0,
            write_nonce: 0,
            // Pre-allocate for one full frame + 2-byte length header.
            read_buf: BytesMut::with_capacity(MAX_FRAME_SIZE + 2),
            decrypt_buf: BytesMut::with_capacity(MAX_FRAME_SIZE),
            write_buf: BytesMut::with_capacity(MAX_FRAME_SIZE + 2),
            write_consumed: 0,
            is_wasm: false,
        }
    }

    // ── Handshake ─────────────────────────────────────────────────────────────

    /// Perform the Noise XX handshake as the initiator.
    ///
    /// # Arguments
    ///
    /// * `inner`      — The underlying transport stream (TCP, QUIC BiStream, etc.).
    /// * `static_key` — The local Noise X25519 static private key (32 bytes).
    /// * `local_nr`   — The local Node Record to send to the responder.
    /// * `ml_dsa_key` — The local ML-DSA-87 signing key (4896 bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The Noise handshake fails (key mismatch, IO error, snow error).
    /// - The responder's Node Record fails ML-DSA-87 self-signature verification.
    /// - The responder's ephemeral binding signature is invalid (misbinding attack).
    /// - Any payload is malformed (wrong key lengths, bad bincode).
    pub async fn handshake_initiator(
        inner: S,
        static_key: &[u8],
        local_nr: &PrimusNR,
        ml_dsa_key: &[u8],
    ) -> Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let mut handshake = builder.local_private_key(static_key).build_initiator()?;

        let sk_bytes: &[u8; 4896] = ml_dsa_key.try_into().map_err(|_| {
            anyhow!(
                "ML-DSA signing key must be 4896 bytes, got {}",
                ml_dsa_key.len()
            )
        })?;
        let signer = SigningKey::<MlDsa87>::decode(sk_bytes.into());

        let mut buf = vec![0u8; MAX_FRAME_SIZE];

        // ── Message 1: -> e ───────────────────────────────────────────────────
        let len = handshake.write_message(&[], &mut buf)?;
        // The first 32 bytes of a Noise message are the ephemeral public key.
        let initiator_e = buf[..32].to_vec();
        let mut writer = tokio_util::codec::FramedWrite::new(
            inner,
            tokio_util::codec::LengthDelimitedCodec::builder()
                .length_field_length(2)
                .max_frame_length(MAX_FRAME_SIZE)
                .new_codec(),
        );
        writer
            .send(Bytes::copy_from_slice(&buf[..len]))
            .await
            .context("Noise handshake: failed to send message 1")?;
        let inner = writer.into_inner();

        // ── Message 2: <- e, ee, s, es + NR_resp + Sig_resp(e_i) ─────────────
        let mut framed = tokio_util::codec::FramedRead::new(
            inner,
            tokio_util::codec::LengthDelimitedCodec::builder()
                .length_field_length(2)
                .max_frame_length(MAX_FRAME_SIZE)
                .new_codec(),
        );

        let bytes = framed
            .next()
            .await
            .context("Noise handshake: responder closed connection")?
            .map_err(|e| anyhow!("Noise handshake: responder frame error: {}", e))?;

        let inner = framed.into_inner();
        buf[..bytes.len()].copy_from_slice(&bytes);
        let len = bytes.len();

        // The responder's ephemeral key is the first 32 bytes of message 2.
        let responder_e = buf[..32].to_vec();

        let mut payload_buf = vec![0u8; MAX_FRAME_SIZE];
        let payload_len = handshake.read_message(&buf[..len], &mut payload_buf)?;

        let payload: NoiseHandshakePayload = bincode::deserialize(&payload_buf[..payload_len])
            .map_err(|_| anyhow!("Responder handshake payload failed bincode deserialization"))?;

        // Verify the responder's Node Record self-signature.
        if !payload.nr.verify() {
            return Err(anyhow!(
                "Responder Node Record self-signature verification failed"
            ));
        }

        // Verify the responder signed our ephemeral key (identity binding).
        let vk_bytes: &[u8; 2592] = payload.nr.public_key[..]
            .try_into()
            .map_err(|_| anyhow!("Responder public key must be 2592 bytes"))?;
        let responder_vk = VerifyingKey::<MlDsa87>::decode(vk_bytes.into());

        let sig_bytes: &[u8; 4627] = payload.ephemeral_sig[..]
            .try_into()
            .map_err(|_| anyhow!("Responder ephemeral signature must be 4627 bytes"))?;
        let sig = ml_dsa::Signature::<MlDsa87>::decode(sig_bytes.into())
            .ok_or_else(|| anyhow!("Responder ephemeral signature is malformed"))?;

        let initiator_e_c = initiator_e.clone();
        let verify_result = tokio::task::spawn_blocking(move || {
            std::thread::Builder::new()
                .name("noise-verify".into())
                .stack_size(16 * 1024 * 1024)
                .spawn(move || responder_vk.verify(&initiator_e_c, &sig))
                .expect("spawn failed")
                .join()
                .expect("panicked")
        })
            .await
            .expect("spawn_blocking failed");

        verify_result.map_err(|e| anyhow!("Responder identity binding check failed: {e}"))?;

        // ── Message 3: -> s, se + NR_init + Sig_init(e_r) ────────────────────
        let responder_e_c = responder_e.clone();
        let initiator_sig = tokio::task::spawn_blocking(move || {
            std::thread::Builder::new()
                .name("noise-sign".into())
                .stack_size(16 * 1024 * 1024)
                .spawn(move || signer.sign(&responder_e_c).to_bytes().to_vec())
                .expect("spawn failed")
                .join()
                .expect("panicked")
        })
            .await
            .expect("spawn_blocking failed");
        let initiator_payload = NoiseHandshakePayload {
            nr: local_nr.clone(),
            ephemeral_sig: initiator_sig,
        };
        let nr_bytes = bincode::serialize(&initiator_payload)
            .map_err(|_| anyhow!("Failed to serialize initiator handshake payload"))?;

        let len = handshake.write_message(&nr_bytes, &mut buf)?;
        let mut writer = FramedWrite::new(
            inner,
            LengthDelimitedCodec::builder()
                .length_field_length(2)
                .max_frame_length(MAX_FRAME_SIZE)
                .new_codec(),
        );

        writer
            .send(Bytes::copy_from_slice(&buf[..len]))
            .await
            .context("Noise handshake: failed to send message 3")?;
        let inner = writer.into_inner();

        let noise = handshake.into_stateless_transport_mode()?;
        Ok(Self::new(inner, noise))
    }

    /// Perform the Noise XX handshake as the responder.
    ///
    /// Mirror of `handshake_initiator`. See that method for argument docs.
    pub async fn handshake_responder(
        inner: S,
        static_key: &[u8],
        local_nr: &PrimusNR,
        ml_dsa_key: &[u8],
    ) -> Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let mut handshake = builder.local_private_key(static_key).build_responder()?;

        let sk_bytes: &[u8; 4896] = ml_dsa_key.try_into().map_err(|_| {
            anyhow!(
                "ML-DSA signing key must be 4896 bytes, got {}",
                ml_dsa_key.len()
            )
        })?;
        let signer = SigningKey::<MlDsa87>::decode(sk_bytes.into());

        let mut buf = vec![0u8; MAX_FRAME_SIZE];

        // ── Message 1: <- e ───────────────────────────────────────────────────
        let mut framed = tokio_util::codec::FramedRead::new(
            inner,
            tokio_util::codec::LengthDelimitedCodec::builder()
                .length_field_length(2)
                .max_frame_length(MAX_FRAME_SIZE)
                .new_codec(),
        );

        let bytes = framed
            .next()
            .await
            .context("Noise handshake: initiator closed connection")?
            .map_err(|e| anyhow!("Noise handshake: initiator frame error: {}", e))?;

        let inner = framed.into_inner();
        buf[..bytes.len()].copy_from_slice(&bytes);
        let len = bytes.len();

        let initiator_e = buf[..32].to_vec();
        handshake.read_message(&buf[..len], &mut [])?;

        // ── Message 2: -> e, ee, s, es + NR_resp + Sig_resp(e_i) ─────────────
        let initiator_e_c = initiator_e.clone();
        let responder_sig = tokio::task::spawn_blocking(move || {
            std::thread::Builder::new()
                .name("noise-sign".into())
                .stack_size(16 * 1024 * 1024)
                .spawn(move || signer.sign(&initiator_e_c).to_bytes().to_vec())
                .expect("spawn failed")
                .join()
                .expect("panicked")
        })
            .await
            .expect("spawn_blocking failed");
        let responder_payload = NoiseHandshakePayload {
            nr: local_nr.clone(),
            ephemeral_sig: responder_sig,
        };
        let nr_bytes = bincode::serialize(&responder_payload)
            .map_err(|_| anyhow!("Failed to serialize responder handshake payload"))?;

        let len = handshake.write_message(&nr_bytes, &mut buf)?;
        // The first 32 bytes of message 2 are the responder's ephemeral key.
        let responder_e = buf[..32].to_vec();

        let mut writer = FramedWrite::new(
            inner,
            LengthDelimitedCodec::builder()
                .length_field_length(2)
                .max_frame_length(MAX_FRAME_SIZE)
                .new_codec(),
        );

        writer
            .send(Bytes::copy_from_slice(&buf[..len]))
            .await
            .context("Noise handshake: failed to send message 2")?;
        let inner = writer.into_inner();

        // ── Message 3: <- s, se + NR_init + Sig_init(e_r) ────────────────────
        let mut framed = FramedRead::new(
            inner,
            LengthDelimitedCodec::builder()
                .length_field_length(2)
                .max_frame_length(MAX_FRAME_SIZE)
                .new_codec(),
        );

        let bytes = framed
            .next()
            .await
            .context("Noise handshake: initiator closed connection")?
            .map_err(|e| anyhow!("Noise handshake: initiator frame error: {}", e))?;

        let inner = framed.into_inner();
        let mut payload_buf = vec![0u8; MAX_FRAME_SIZE];
        let payload_len = handshake.read_message(&bytes, &mut payload_buf)?;

        let payload: NoiseHandshakePayload = bincode::deserialize(&payload_buf[..payload_len])
            .map_err(|_| anyhow!("Initiator handshake payload failed bincode deserialization"))?;

        // Verify the initiator's Node Record self-signature.
        if !payload.nr.verify() {
            return Err(anyhow!(
                "Initiator Node Record self-signature verification failed"
            ));
        }

        // Verify the initiator signed our ephemeral key (identity binding).
        let vk_bytes: &[u8; 2592] = payload.nr.public_key[..]
            .try_into()
            .map_err(|_| anyhow!("Initiator public key must be 2592 bytes"))?;
        let initiator_vk = VerifyingKey::<MlDsa87>::decode(vk_bytes.into());

        let sig_bytes: &[u8; 4627] = payload.ephemeral_sig[..]
            .try_into()
            .map_err(|_| anyhow!("Initiator ephemeral signature must be 4627 bytes"))?;
        let sig = ml_dsa::Signature::<MlDsa87>::decode(sig_bytes.into())
            .ok_or_else(|| anyhow!("Initiator ephemeral signature is malformed"))?;

        let responder_e_c = responder_e.clone();
        let verify_result = tokio::task::spawn_blocking(move || {
            std::thread::Builder::new()
                .name("noise-verify".into())
                .stack_size(16 * 1024 * 1024)
                .spawn(move || initiator_vk.verify(&responder_e_c, &sig))
                .expect("spawn failed")
                .join()
                .expect("panicked")
        })
            .await
            .expect("spawn_blocking failed");

        verify_result.map_err(|e| anyhow!("Initiator identity binding check failed: {e}"))?;

        let noise = handshake.into_stateless_transport_mode()?;
        Ok(Self::new(inner, noise))
    }

    // ── Frame helpers ─────────────────────────────────────────────────────────

    /// Byte length of the frame header (length field + optional WASM padding).
    #[inline]
    fn header_len(&self) -> usize {
        if self.is_wasm { 2 + 6 } else { 2 }
    }
}

// ── AsyncRead ─────────────────────────────────────────────────────────────────

impl<S> AsyncRead for NoiseStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // ── Drain decrypted data first ────────────────────────────────────
            if !self.decrypt_buf.is_empty() {
                let n = self.decrypt_buf.len().min(buf.remaining());
                buf.put_slice(&self.decrypt_buf[..n]);
                self.decrypt_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            let me = self.as_mut().get_mut();
            let header = me.header_len();

            // ── Read frame header ─────────────────────────────────────────────
            if me.read_buf.len() < header {
                let needed = header - me.read_buf.len();
                let mut temp = vec![0u8; needed];
                let mut temp_buf = tokio::io::ReadBuf::new(&mut temp);
                match Pin::new(&mut me.inner).poll_read(cx, &mut temp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        me.read_buf.extend_from_slice(temp_buf.filled());
                        if me.read_buf.len() < header {
                            continue;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // ── Read frame body ───────────────────────────────────────────────
            let frame_len = u16::from_be_bytes([me.read_buf[0], me.read_buf[1]]) as usize;
            let total_len = header + frame_len;

            if me.read_buf.len() < total_len {
                let needed = total_len - me.read_buf.len();
                let mut temp = vec![0u8; needed];
                let mut temp_buf = tokio::io::ReadBuf::new(&mut temp);
                match Pin::new(&mut me.inner).poll_read(cx, &mut temp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed mid-frame",
                            )));
                        }
                        me.read_buf.extend_from_slice(temp_buf.filled());
                        if me.read_buf.len() < total_len {
                            continue;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // ── Decrypt ───────────────────────────────────────────────────────
            let frame = me.read_buf[header..total_len].to_vec();
            let mut decrypted = vec![0u8; frame.len()];
            let n = me
                .noise
                .read_message(me.read_nonce, &frame, &mut decrypted)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            me.read_nonce += 1;
            me.decrypt_buf.extend_from_slice(&decrypted[..n]);
            me.read_buf.advance(total_len);
        }
    }
}

// ── AsyncWrite ────────────────────────────────────────────────────────────────

impl<S> AsyncWrite for NoiseStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Flush any pending write before accepting new data.
        if !self.write_buf.is_empty() {
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Encrypt at most MAX_PLAINTEXT bytes per Noise message.
        let n = buf.len().min(MAX_PLAINTEXT);
        let mut encrypted = vec![0u8; n + TAG_LEN];
        let enc_len = self
            .noise
            .write_message(self.write_nonce, &buf[..n], &mut encrypted)
            .map_err(std::io::Error::other)?;
        self.write_nonce += 1;

        // Frame: [u16 BE length] [optional 6-byte WASM padding] [ciphertext]
        self.write_buf.put_u16(enc_len as u16);
        if self.is_wasm {
            self.write_buf.put_bytes(0, 6);
        }
        self.write_buf.extend_from_slice(&encrypted[..enc_len]);
        self.write_consumed = 0;

        // Best-effort flush — errors are surfaced on the next poll_write or
        // explicit poll_flush, not here, so callers see them predictably.
        let _ = self.as_mut().poll_flush(cx);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        while me.write_consumed < me.write_buf.len() {
            let data = &me.write_buf[me.write_consumed..];
            match Pin::new(&mut me.inner).poll_write(cx, data) {
                Poll::Ready(Ok(n)) => {
                    me.write_consumed += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        me.write_buf.clear();
        me.write_consumed = 0;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                let me = self.get_mut();
                Pin::new(&mut me.inner).poll_shutdown(cx)
            }
            res => res,
        }
    }
}