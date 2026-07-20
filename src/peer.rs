// =============================================================================
// primus-net-opt/src/peer.rs — Node Record (standalone replacement for
// primus_types::PrimusNR)
//
// STANDALONE MIGRATION:
//   primus-net-opt no longer depends on the primus-types crate (or on
//   primus-project at all). PrimusNR was the one type from primus-types
//   still used here after the blockchain-protocol removal — everywhere it
//   appeared it meant "a peer's identity + address", never chain state.
//   It is now defined locally.
//
// WHAT IT IS:
//   A self-signed Node Record: an ML-DSA-87 public key, a network address,
//   and a signature over both, produced by the holder of the matching
//   signing key. This is the identity object exchanged during the Noise
//   handshake (see noise.rs) and stored in the Kademlia routing table
//   (see dht.rs). `node_id()` — the 256-bit Kademlia key — is derived as
//   SHA3-256(public_key), matching dht.rs's 256-bucket routing table.
//
// NOTE ON THE ML-DSA API:
//   `ml-dsa = "0.0.4"` is a young crate; the exact encode/decode method
//   names below (`verifying_key()`, `.encode()`, `SigningKey::decode()`)
//   match the patterns already used elsewhere in this crate (see
//   noise.rs's existing `SigningKey::<MlDsa87>::decode(...)` /
//   `VerifyingKey::<MlDsa87>::decode(...)` calls) but have not been
//   compiled against the crate here — double check against the installed
//   version when you build this.
// =============================================================================

use anyhow::{anyhow, Result};
use ml_dsa::signature::{SignatureEncoding, Signer, Verifier};
use ml_dsa::{MlDsa87, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::net::SocketAddr;

use crate::dht::NodeID;

/// ML-DSA-87 verifying (public) key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 2592;
/// ML-DSA-87 signature length in bytes.
pub const SIGNATURE_LEN: usize = 4627;
/// ML-DSA-87 signing (secret) key length in bytes.
pub const SIGNING_KEY_LEN: usize = 4896;

/// A self-signed peer identity record.
///
/// `signature` is computed over `addr || public_key` with the signing key
/// matching `public_key`. `verify()` checks that binding — it proves
/// whoever holds the signing key vouches for this address, nothing more.
/// It intentionally does *not* prove the record's sender is reachable at
/// that address; that's what the Noise ephemeral-key binding signature
/// (see noise.rs) and Kademlia's ping-on-evict path are for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrimusNR {
    pub public_key: Vec<u8>,
    pub addr: SocketAddr,
    pub signature: Vec<u8>,
}

impl PrimusNR {
    /// Build and self-sign a new Node Record for `addr` using `ml_dsa_sk`
    /// (a raw 4896-byte ML-DSA-87 signing key).
    pub fn new(addr: SocketAddr, ml_dsa_pk: &[u8], ml_dsa_sk: &[u8]) -> Result<Self> {
        let sk_bytes: &[u8; SIGNING_KEY_LEN] = ml_dsa_sk
            .try_into()
            .map_err(|_| anyhow!("ML-DSA signing key must be {} bytes, got {}", SIGNING_KEY_LEN, ml_dsa_sk.len()))?;
        let signer = SigningKey::<MlDsa87>::decode(sk_bytes.into());
        let public_key = ml_dsa_pk.to_vec();

        let msg = Self::signing_bytes(&addr, &public_key);
        let signature = signer.sign(&msg).to_bytes().to_vec();

        Ok(Self { public_key, addr, signature })
    }

    /// The bytes that get signed / verified: address string || public key.
    fn signing_bytes(addr: &SocketAddr, public_key: &[u8]) -> Vec<u8> {
        let mut msg = addr.to_string().into_bytes();
        msg.extend_from_slice(public_key);
        msg
    }

    /// Verify the self-signature over `addr || public_key`.
    pub fn verify(&self) -> bool {
        let Ok(vk_bytes) = <&[u8; PUBLIC_KEY_LEN]>::try_from(&self.public_key[..]) else {
            return false;
        };
        let Ok(sig_bytes) = <&[u8; SIGNATURE_LEN]>::try_from(&self.signature[..]) else {
            return false;
        };
        let Some(sig) = ml_dsa::Signature::<MlDsa87>::decode(sig_bytes.into()) else {
            return false;
        };
        let vk = VerifyingKey::<MlDsa87>::decode(vk_bytes.into());
        let msg = Self::signing_bytes(&self.addr, &self.public_key);
        vk.verify(&msg, &sig).is_ok()
    }

    /// Kademlia node ID: SHA3-256 of the public key (256 bits, matching
    /// dht.rs's `NBUCKETS = 256`).
    pub fn node_id(&self) -> NodeID {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.public_key);
        hasher.finalize().into()
    }

    /// The peer's network address (QUIC port — see the note in
    /// `network.rs::broadcast_message` about this differing from the TCP
    /// listener port).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Vec<u8>, SocketAddr) {
        // NOTE: replace with a real ML-DSA-87 keygen call once wired into a
        // build — this module has not been compiled against the crate yet.
        // Left as a placeholder so the test file states its own assumption
        // rather than silently compiling against the wrong shape.
        (vec![0u8; SIGNING_KEY_LEN], "127.0.0.1:9000".parse().unwrap())
    }

    #[test]
    fn node_id_is_deterministic() {
        let public_key = vec![7u8; PUBLIC_KEY_LEN];
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let nr = PrimusNR { public_key: public_key.clone(), addr, signature: vec![] };
        let nr2 = PrimusNR { public_key, addr, signature: vec![] };
        assert_eq!(nr.node_id(), nr2.node_id());
    }

    #[test]
    fn verify_rejects_malformed_key_lengths() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let nr = PrimusNR { public_key: vec![1, 2, 3], addr, signature: vec![4, 5, 6] };
        assert!(!nr.verify());
    }
}