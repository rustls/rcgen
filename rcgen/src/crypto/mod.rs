//! Pluggable cryptography providers.
//!
//! rcgen keeps certificate encoding independent from cryptographic implementations. A
//! [`CryptoProvider`] supplies the operations rcgen performs itself: key generation and
//! loading, hashing, and signature verification when parsing certificate signing requests.
//!
//! Applications using a custom provider should disable rcgen's default features, enable
//! `crypto`, and install their provider before using convenience APIs such as
//! [`KeyPair::generate`](crate::KeyPair::generate):
//!
//! ```ignore
//! custom_provider().install_default()
//!     .expect("a crypto provider was already installed");
//! ```
//!
//! A provider can also be passed explicitly to APIs whose names end in `with_provider`.
//! Explicit selection is useful for libraries and does not access the process-wide default.

use std::fmt::Debug;
use std::sync::{Arc, OnceLock};

use pki_types::PrivateKeyDer;

use crate::{Error, KeyPair, RsaKeySize, SignatureAlgorithm};

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

/// Hash operations supplied by a [`CryptoProvider`].
pub trait DigestProvider: Debug + Send + Sync {
	/// Hash `input` with `algorithm`, writing the digest to `output`.
	///
	/// `output` is always exactly [`HashAlgorithm::output_len`] bytes long.
	fn digest(
		&self,
		algorithm: HashAlgorithm,
		input: &[u8],
		output: &mut [u8],
	) -> Result<(), Error>;
}

/// Key generation and private-key loading supplied by a [`CryptoProvider`].
pub trait KeyPairProvider: Debug + Send + Sync {
	/// Generate an exportable key pair for `algorithm`.
	fn generate(&self, algorithm: &'static SignatureAlgorithm) -> Result<KeyPair, Error>;

	/// Generate an exportable RSA key pair of `key_size` for `algorithm`.
	///
	/// Providers that do not support selectable RSA key sizes may retain the default
	/// implementation.
	fn generate_rsa(
		&self,
		algorithm: &'static SignatureAlgorithm,
		key_size: RsaKeySize,
	) -> Result<KeyPair, Error> {
		let _ = (algorithm, key_size);
		Err(Error::KeyGenerationUnavailable)
	}

	/// Decode and validate an exportable private key.
	///
	/// If `algorithm` is `Some`, the key must be loaded for exactly that signature algorithm.
	/// If it is `None`, the provider detects a supported algorithm from the key.
	fn load_private_key(
		&self,
		key_der: PrivateKeyDer<'static>,
		algorithm: Option<&'static SignatureAlgorithm>,
	) -> Result<KeyPair, Error>;
}

/// Signature verification supplied by a [`CryptoProvider`].
///
/// rcgen uses this operation to verify the self-signature on a parsed PKCS#10 certificate
/// signing request. Public keys are provided as the contents of the SubjectPublicKeyInfo
/// `subjectPublicKey` BIT STRING, matching [`PublicKeyData::der_bytes`](crate::PublicKeyData::der_bytes).
pub trait SignatureVerificationProvider: Debug + Send + Sync {
	/// Verify `signature` over `message` using `public_key` and `algorithm`.
	fn verify(
		&self,
		algorithm: &'static SignatureAlgorithm,
		public_key: &[u8],
		message: &[u8],
		signature: &[u8],
	) -> Result<(), Error>;
}

/// Controls the cryptography used by rcgen.
///
/// The component fields can come from one backend or be composed from several backends. rcgen
/// provides built-in providers through `crypto::ring::default_provider()` and
/// `crypto::aws_lc_rs::default_provider()` when their corresponding crate features are enabled. A custom
/// provider does not require either dependency.
///
/// # Process-wide default
///
/// [`install_default`](Self::install_default) sets a provider once for convenience APIs. If no
/// provider has been installed, rcgen automatically installs a built-in provider selected by
/// crate features. As in earlier rcgen releases, AWS-LC takes precedence if both built-in backend
/// features are enabled. With no backend or the `custom-provider` feature, applications must
/// install a provider explicitly.
#[derive(Clone, Debug)]
pub struct CryptoProvider {
	/// Provider for generating and loading private key pairs.
	pub key_pair_provider: &'static dyn KeyPairProvider,
	/// Provider for SHA-256, SHA-384, and SHA-512 hashing.
	pub digest_provider: &'static dyn DigestProvider,
	/// Provider for signature verification.
	pub signature_verification_provider: &'static dyn SignatureVerificationProvider,
}

impl CryptoProvider {
	/// Set this provider as the default for the current process.
	///
	/// This can succeed at most once during a process execution. Call it before invoking any
	/// convenience API that uses the process-wide provider.
	pub fn install_default(self) -> Result<(), Arc<Self>> {
		PROCESS_DEFAULT_PROVIDER.set(Arc::new(self))
	}

	/// Return the process-wide default provider, if one has been installed.
	pub fn get_default() -> Option<&'static Arc<Self>> {
		PROCESS_DEFAULT_PROVIDER.get()
	}

	/// Compute a digest using this provider.
	pub fn digest(&self, algorithm: HashAlgorithm, input: &[u8]) -> Result<Vec<u8>, Error> {
		let mut output = vec![0; algorithm.output_len()];
		self.digest_provider.digest(algorithm, input, &mut output)?;
		Ok(output)
	}

	pub(crate) fn get_default_or_install_from_crate_features() -> Result<&'static Arc<Self>, Error>
	{
		if let Some(provider) = Self::get_default() {
			return Ok(provider);
		}

		let provider = Self::from_crate_features().ok_or(Error::CryptoProviderNotInstalled)?;
		// Another thread may install a provider first. In that case its choice wins.
		let _ = provider.install_default();
		Self::get_default().ok_or(Error::CryptoProviderNotInstalled)
	}

	fn from_crate_features() -> Option<Self> {
		#[cfg(all(
			feature = "ring",
			not(feature = "aws_lc_rs"),
			not(feature = "custom-provider")
		))]
		{
			return Some(ring::default_provider());
		}

		#[cfg(all(feature = "aws_lc_rs", not(feature = "custom-provider")))]
		{
			return Some(aws_lc_rs::default_provider());
		}

		#[allow(unreachable_code)]
		None
	}
}

static PROCESS_DEFAULT_PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();

/// `ring`-based cryptography provider.
#[cfg(feature = "ring")]
pub mod ring;

/// AWS-LC-based cryptography provider.
#[cfg(feature = "aws_lc_rs")]
pub mod aws_lc_rs;
