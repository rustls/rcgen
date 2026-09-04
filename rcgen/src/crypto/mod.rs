//! Pluggable cryptography providers.
//!
//! rcgen keeps certificate encoding independent from cryptographic implementations. A
//! [`CryptoProvider`] supplies the operations rcgen performs itself: key generation and
//! loading, hashing, and signature verification when parsing certificate signing requests.
//!
//! Applications select a provider explicitly for each API that performs cryptographic work.

use pki_types::PrivateKeyDer;

use crate::{Error, KeyPair, RsaKeySize, SignatureAlgorithm};

/// `ring`-based cryptography provider.
#[cfg(feature = "ring")]
pub mod ring;

/// AWS-LC-based cryptography provider.
#[cfg(feature = "aws_lc_rs")]
pub mod aws_lc_rs;

/// Cryptographic operations used by rcgen.
pub trait CryptoProvider: std::fmt::Debug + Send + Sync {
	/// Hash `input` with `algorithm`.
	fn hash(&self, algorithm: HashAlgorithm, input: &[u8]) -> HashOutput;

	/// Generate an exportable key pair for `algorithm`.
	///
	/// `key_size` selects an explicit RSA key size. It must be `None` for non-RSA algorithms.
	fn generate(
		&self,
		algorithm: &'static SignatureAlgorithm,
		key_size: Option<RsaKeySize>,
	) -> Result<KeyPair, Error>;

	/// Decode and validate an exportable private key.
	///
	/// The same key material can support multiple signature algorithms. If `algorithm` is `Some`,
	/// the key must be loaded for exactly that signature algorithm. If it is `None`, the provider
	/// detects a supported algorithm from the key.
	fn load_private_key(
		&self,
		key_der: PrivateKeyDer<'static>,
		algorithm: Option<&'static SignatureAlgorithm>,
	) -> Result<KeyPair, Error>;

	/// Verify `signature` over `message` using `public_key` and `algorithm`.
	///
	/// rcgen uses this operation to verify the self-signature on a parsed PKCS#10 certificate
	/// signing request. `public_key` contains the SubjectPublicKeyInfo `subjectPublicKey` BIT
	/// STRING contents, matching [`PublicKeyData::der_bytes`](crate::PublicKeyData::der_bytes).
	fn verify(
		&self,
		algorithm: &'static SignatureAlgorithm,
		public_key: &[u8],
		message: &[u8],
		signature: &[u8],
	) -> Result<(), Error>;
}
/// A hash algorithm required by rcgen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
	/// SHA-256.
	Sha256,
	/// SHA-384.
	Sha384,
	/// SHA-512.
	Sha512,
}

impl HashAlgorithm {
	/// Return the digest output length in bytes.
	pub const fn output_len(self) -> usize {
		match self {
			Self::Sha256 => 32,
			Self::Sha384 => 48,
			Self::Sha512 => 64,
		}
	}
}

/// The output of a cryptographic hash function.
#[derive(Clone)]
pub struct HashOutput {
	buf: [u8; Self::MAX_LEN],
	used: usize,
}

impl HashOutput {
	/// Construct a hash output from at most [`Self::MAX_LEN`] bytes.
	pub fn new(bytes: &[u8]) -> Self {
		assert!(bytes.len() <= Self::MAX_LEN);
		let mut output = Self {
			buf: [0; Self::MAX_LEN],
			used: bytes.len(),
		};
		output.buf[..bytes.len()].copy_from_slice(bytes);
		output
	}

	/// Maximum supported hash output size, sufficient for SHA-512.
	pub const MAX_LEN: usize = 64;
}

impl AsRef<[u8]> for HashOutput {
	fn as_ref(&self) -> &[u8] {
		&self.buf[..self.used]
	}
}
