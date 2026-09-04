use std::fmt;

#[cfg(feature = "pem")]
use pem::Pem;
use pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use yasna::{DERWriter, DERWriterSeq};

use crate::crypto::CryptoProvider;
#[cfg(feature = "pem")]
use crate::error::ExternalError;
use crate::sign_algo::algo::*;
use crate::sign_algo::SignatureAlgorithm;
use crate::Error;
#[cfg(feature = "pem")]
use crate::ENCODE_CONFIG;

/// A key pair used to sign certificates and CSRs
///
/// The cryptographic implementation is supplied by the selected [`CryptoProvider`].
pub struct KeyPair {
	pub(crate) signing_key: Box<dyn SigningKey + Send + Sync>,
	pub(crate) serialized_der: Vec<u8>,
}

impl fmt::Debug for KeyPair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("KeyPair")
			.field("alg", &self.algorithm())
			.field("serialized_der", &"[secret key elided]")
			.finish()
	}
}

impl KeyPair {
	/// Construct a key pair from a provider-specific signing key and its PKCS#8 DER encoding.
	///
	/// This constructor is intended for implementations of [`CryptoProvider`]. `serialized_der`
	/// must encode the same
	/// private key exposed by `signing_key` and must remain exportable to callers.
	pub fn from_signing_key(
		signing_key: Box<dyn SigningKey + Send + Sync>,
		serialized_der: Vec<u8>,
	) -> Self {
		Self {
			signing_key,
			serialized_der,
		}
	}

	/// Generate a new random [`PKCS_ECDSA_P256_SHA256`] key pair using `provider`.
	pub fn generate(provider: &dyn CryptoProvider) -> Result<Self, Error> {
		Self::generate_for(&PKCS_ECDSA_P256_SHA256, provider)
	}

	/// Generate a new random key pair for the specified signature algorithm
	///
	/// If you're not sure which algorithm to use, [`PKCS_ECDSA_P256_SHA256`] is a good choice.
	/// If passed an RSA signature algorithm, it depends on the provider whether we return
	/// a generated key or an error for key generation being unavailable.
	/// Currently, the built-in `aws-lc-rs` provider supports RSA key generation while the
	/// built-in `ring` provider does not.
	pub fn generate_for(
		alg: &'static SignatureAlgorithm,
		provider: &dyn CryptoProvider,
	) -> Result<Self, Error> {
		provider.generate(alg, None)
	}

	/// Generates a new random RSA key pair for the specified key size
	///
	/// If passed a signature algorithm that is not RSA, it will return
	/// [`Error::KeyGenerationUnavailable`].
	///
	/// It depends on the selected provider whether RSA key generation is available.
	pub fn generate_rsa_for(
		alg: &'static SignatureAlgorithm,
		key_size: RsaKeySize,
		provider: &dyn CryptoProvider,
	) -> Result<Self, Error> {
		provider.generate(alg, Some(key_size))
	}

	/// Returns the key pair's signature algorithm
	pub fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.signing_key.algorithm()
	}

	/// Parses the key pair from the ASCII PEM format
	///
	/// The accepted private-key encodings depend on the selected provider.
	///
	/// If the built-in `aws_lc_rs` provider is used, then the key must be a DER-encoded plaintext
	/// private key as specified in PKCS #8/RFC 5958, SEC1/RFC 5915, or PKCS#1/RFC 3447;
	/// these appear as "PRIVATE KEY", "RSA PRIVATE KEY", or "EC PRIVATE KEY" in PEM files.
	///
	/// If the built-in `ring` provider is used, then the key must be a DER-encoded plaintext
	/// private key as specified in PKCS #8/RFC 5958; this appears as "PRIVATE KEY" in PEM files.
	#[cfg(feature = "pem")]
	pub fn from_pem(pem_str: &str, provider: &dyn CryptoProvider) -> Result<Self, Error> {
		let private_key = pem::parse(pem_str)._err()?;
		let private_key = PrivateKeyDer::try_from(private_key.into_contents())
			.map_err(|_| Error::CouldNotParseKeyPair)?;
		Self::from_der(&private_key, provider)
	}

	/// Obtains the key pair from a PEM formatted key
	/// using the specified [`SignatureAlgorithm`]
	///
	/// The key must be a DER-encoded plaintext private key as specified in PKCS #8/RFC 5958;
	/// it appears as "PRIVATE KEY" in PEM files.
	///
	/// Same as [`from_pem_and_sign_algo`](Self::from_pem_and_sign_algo), but only accepts PKCS#8.
	#[cfg(feature = "pem")]
	pub fn from_pkcs8_pem_and_sign_algo(
		pem_str: &str,
		alg: &'static SignatureAlgorithm,
		provider: &dyn CryptoProvider,
	) -> Result<Self, Error> {
		let private_key = pem::parse(pem_str)._err()?;
		let private_key = PrivatePkcs8KeyDer::from(private_key.into_contents());
		Self::from_pkcs8_der_and_sign_algo(&private_key, alg, provider)
	}

	/// Obtains the key pair from a DER formatted key using the specified [`SignatureAlgorithm`]
	///
	/// Use [`from_der`](Self::from_der) when the provider should determine the appropriate
	/// [`SignatureAlgorithm`]. Use this function when multiple signature algorithms fit the same
	/// key and you need to select one precisely.
	///
	/// [`rustls_pemfile::private_key()`] is often used to obtain a [`PrivateKeyDer`] from PEM
	/// input. If the obtained [`PrivateKeyDer`] is a `Pkcs8` variant, you can use its contents
	/// as input for this function. Alternatively, if you already have a byte slice containing DER,
	/// it can trivially be converted into [`PrivatePkcs8KeyDer`] using the [`Into`] trait.
	///
	/// [`rustls_pemfile::private_key()`]: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/fn.private_key.html
	/// [`PrivateKeyDer`]: https://docs.rs/rustls-pki-types/latest/rustls_pki_types/enum.PrivateKeyDer.html
	pub fn from_pkcs8_der_and_sign_algo(
		pkcs8: &PrivatePkcs8KeyDer<'_>,
		alg: &'static SignatureAlgorithm,
		provider: &dyn CryptoProvider,
	) -> Result<Self, Error> {
		provider.load_private_key(PrivateKeyDer::Pkcs8(pkcs8.clone_key()), Some(alg))
	}

	/// Obtains the key pair from a PEM formatted key
	/// using the specified [`SignatureAlgorithm`]
	///
	/// The accepted private-key encodings depend on the selected provider.
	///
	/// If the built-in `aws_lc_rs` provider is used, then the key must be a DER-encoded plaintext
	/// private key as specified in PKCS #8/RFC 5958, SEC1/RFC 5915, or PKCS#1/RFC 3447;
	/// these appear as "PRIVATE KEY", "RSA PRIVATE KEY", or "EC PRIVATE KEY" in PEM files.
	///
	/// If the built-in `ring` provider is used, then the key must be a DER-encoded plaintext
	/// private key as specified in PKCS #8/RFC 5958; this appears as "PRIVATE KEY" in PEM files.
	///
	/// Same as [`from_pkcs8_pem_and_sign_algo`](Self::from_pkcs8_pem_and_sign_algo) for PKCS#8 keys.
	#[cfg(feature = "pem")]
	pub fn from_pem_and_sign_algo(
		pem_str: &str,
		alg: &'static SignatureAlgorithm,
		provider: &dyn CryptoProvider,
	) -> Result<Self, Error> {
		let private_key = pem::parse(pem_str)._err()?;
		let private_key = PrivateKeyDer::try_from(private_key.into_contents())
			.map_err(|_| Error::CouldNotParseKeyPair)?;
		Self::from_der_and_sign_algo(&private_key, alg, provider)
	}

	/// Obtains the key pair from a DER formatted key
	/// using the specified [`SignatureAlgorithm`]
	///
	/// The accepted [`PrivateKeyDer`] variants depend on the selected provider. The built-in
	/// `ring` provider only supports [`PrivateKeyDer::Pkcs8`], while the built-in `aws_lc_rs`
	/// provider supports PKCS#8, PKCS#1, and SEC1 keys.
	///
	/// Use [`from_der`](Self::from_der) when the provider should determine the appropriate
	/// [`SignatureAlgorithm`]. Use this function when multiple signature algorithms fit the same
	/// key and you need to select one precisely.
	///
	/// You can use [`rustls_pemfile::private_key`] to get the `key` input. If
	/// you already have a byte slice, just calling `try_into()` will convert it to a [`PrivateKeyDer`].
	///
	/// [`rustls_pemfile::private_key`]: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/fn.private_key.html
	pub fn from_der_and_sign_algo(
		key: &PrivateKeyDer<'_>,
		alg: &'static SignatureAlgorithm,
		provider: &dyn CryptoProvider,
	) -> Result<Self, Error> {
		provider.load_private_key(key.clone_key(), Some(alg))
	}

	/// Obtains the key pair from a DER formatted key using `provider`.
	///
	/// The provider determines the correct [`SignatureAlgorithm`] for the key.
	pub fn from_der(key: &PrivateKeyDer<'_>, provider: &dyn CryptoProvider) -> Result<Self, Error> {
		provider.load_private_key(key.clone_key(), None)
	}

	/// Get the raw public key of this key pair
	///
	/// The returned bytes are the contents of the X.509 SubjectPublicKeyInfo
	/// `subjectPublicKey` BIT STRING, matching [`PublicKeyData::der_bytes`]. This is also the
	/// public-key format passed to
	/// [`CryptoProvider::verify`].
	pub fn public_key_raw(&self) -> &[u8] {
		self.der_bytes()
	}

	/// Check if this key pair can be used with the given signature algorithm
	pub fn is_compatible(&self, signature_algorithm: &SignatureAlgorithm) -> bool {
		self.algorithm() == signature_algorithm
	}

	/// Returns (possibly multiple) compatible [`SignatureAlgorithm`]'s
	/// that the key can be used with
	pub fn compatible_algs(&self) -> impl Iterator<Item = &'static SignatureAlgorithm> {
		std::iter::once(self.algorithm())
	}

	/// Return the key pair's public key in PEM format
	///
	/// The returned string can be interpreted with `openssl pkey --inform PEM -pubout -pubin -text`
	#[cfg(feature = "pem")]
	pub fn public_key_pem(&self) -> String {
		let contents = self.subject_public_key_info();
		let p = Pem::new("PUBLIC KEY", contents);
		pem::encode_config(&p, ENCODE_CONFIG)
	}

	/// Serializes the key pair (including the private key) in PKCS#8 format in DER
	pub fn serialize_der(&self) -> Vec<u8> {
		self.serialized_der.clone()
	}

	/// Returns a reference to the serialized key pair (including the private key)
	/// in PKCS#8 format in DER
	pub fn serialized_der(&self) -> &[u8] {
		&self.serialized_der
	}

	/// Serializes the key pair (including the private key) in PKCS#8 format in PEM
	#[cfg(feature = "pem")]
	pub fn serialize_pem(&self) -> String {
		let p = Pem::new("PRIVATE KEY", self.serialize_der());
		pem::encode_config(&p, ENCODE_CONFIG)
	}
}

impl SigningKey for KeyPair {
	fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
		self.signing_key.sign(msg)
	}
}

impl PublicKeyData for KeyPair {
	fn der_bytes(&self) -> &[u8] {
		self.signing_key.der_bytes()
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.signing_key.algorithm()
	}
}

impl From<KeyPair> for PrivatePkcs8KeyDer<'static> {
	fn from(val: KeyPair) -> Self {
		val.serialize_der().into()
	}
}

impl From<KeyPair> for PrivateKeyDer<'static> {
	fn from(val: KeyPair) -> Self {
		Self::from(PrivatePkcs8KeyDer::from(val))
	}
}

/// The key size used for RSA key generation
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RsaKeySize {
	/// 2048 bits
	_2048,
	/// 3072 bits
	_3072,
	/// 4096 bits
	_4096,
}

pub(crate) fn sign_der(
	key: &(impl SigningKey + ?Sized),
	f: impl FnOnce(&mut DERWriterSeq<'_>) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
	yasna::try_construct_der(|writer| {
		writer.write_sequence(|writer| {
			let data = yasna::try_construct_der(|writer| writer.write_sequence(f))?;
			writer.next().write_der(&data);

			// Write signatureAlgorithm
			key.algorithm().write_alg_ident(writer.next());

			// Write signature
			let sig = key.sign(&data)?;
			let writer = writer.next();
			writer.write_bitvec_bytes(&sig, sig.len() * 8);

			Ok(())
		})
	})
}

impl<S: SigningKey + ?Sized> SigningKey for &S {
	fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
		(*self).sign(msg)
	}
}

impl<S: SigningKey + ?Sized> SigningKey for Box<S> {
	fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
		(**self).sign(msg)
	}
}

/// A key that can be used to sign messages
pub trait SigningKey: PublicKeyData {
	/// Signs `msg` using the selected algorithm
	fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error>;
}

#[cfg(feature = "pem")]
impl<T> ExternalError<T> for Result<T, pem::PemError> {
	fn _err(self) -> Result<T, Error> {
		self.map_err(|e| Error::PemError(e.to_string()))
	}
}

/// A public key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
	pub(crate) alg: &'static SignatureAlgorithm,
	pub(crate) subject_public_key: Vec<u8>,
}

impl SubjectPublicKeyInfo {
	/// Create a `SubjectPublicKey` value from a PEM-encoded SubjectPublicKeyInfo string
	#[cfg(all(feature = "x509-parser", feature = "pem"))]
	pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
		Self::from_der(&pem::parse(pem_str)._err()?.into_contents())
	}

	/// Create a `SubjectPublicKey` value from DER-encoded SubjectPublicKeyInfo bytes
	#[cfg(feature = "x509-parser")]
	pub fn from_der(spki_der: &[u8]) -> Result<Self, Error> {
		use x509_parser::prelude::FromDer;
		use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

		let (rem, spki) =
			SubjectPublicKeyInfo::from_der(spki_der).map_err(|e| Error::X509(e.to_string()))?;
		if !rem.is_empty() {
			return Err(Error::X509(
				"trailing bytes in SubjectPublicKeyInfo".to_string(),
			));
		}

		let alg = SignatureAlgorithm::iter()
			.find(|alg| {
				let bytes = yasna::construct_der(|writer| alg.write_oids_sign_alg(writer));
				let Ok((rest, aid)) = AlgorithmIdentifier::from_der(&bytes) else {
					return false;
				};
				rest.is_empty() && aid == spki.algorithm
			})
			.ok_or(Error::UnsupportedSignatureAlgorithm)?;

		Ok(Self {
			alg,
			subject_public_key: Vec::from(spki.subject_public_key.as_ref()),
		})
	}
}

impl PublicKeyData for SubjectPublicKeyInfo {
	fn der_bytes(&self) -> &[u8] {
		&self.subject_public_key
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.alg
	}
}

impl<K: PublicKeyData + ?Sized> PublicKeyData for &K {
	fn der_bytes(&self) -> &[u8] {
		(*self).der_bytes()
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		(*self).algorithm()
	}
}

impl<K: PublicKeyData + ?Sized> PublicKeyData for Box<K> {
	fn der_bytes(&self) -> &[u8] {
		(**self).der_bytes()
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		(**self).algorithm()
	}
}

/// The public key data of a key pair
pub trait PublicKeyData {
	/// The public key data in DER format
	///
	/// The key is formatted according to the X.509 SubjectPublicKeyInfo struct.
	/// See [RFC 5280 section 4.1](https://tools.ietf.org/html/rfc5280#section-4.1).
	fn subject_public_key_info(&self) -> Vec<u8> {
		yasna::construct_der(|writer| serialize_public_key_der(self, writer))
	}

	/// The public key in DER format
	fn der_bytes(&self) -> &[u8];

	/// The algorithm used by the key pair
	fn algorithm(&self) -> &'static SignatureAlgorithm;
}

pub(crate) fn serialize_public_key_der(key: &(impl PublicKeyData + ?Sized), writer: DERWriter) {
	writer.write_sequence(|writer| {
		key.algorithm().write_oids_sign_alg(writer.next());
		let pk = key.der_bytes();
		writer.next().write_bitvec_bytes(pk, pk.len() * 8);
	})
}

#[cfg(all(test, any(feature = "ring", feature = "aws_lc_rs")))]
mod test {
	use super::*;

	#[cfg(all(feature = "x509-parser", feature = "pem"))]
	#[test]
	fn test_subject_public_key_parsing() {
		for alg in [
			&PKCS_ED25519,
			&PKCS_ECDSA_P256_SHA256,
			&PKCS_ECDSA_P384_SHA384,
			#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
			&PKCS_ECDSA_P521_SHA512,
			#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
			&PKCS_RSA_SHA256,
		] {
			let kp = KeyPair::generate_for(alg, crate::test_provider()).expect("keygen");
			let pem = kp.public_key_pem();
			let der = kp.subject_public_key_info();

			let pkd_pem = SubjectPublicKeyInfo::from_pem(&pem).expect("from pem");
			assert_eq!(kp.der_bytes(), pkd_pem.der_bytes());

			let pkd_der = SubjectPublicKeyInfo::from_der(&der).expect("from der");
			assert_eq!(kp.der_bytes(), pkd_der.der_bytes());
		}
	}

	#[test]
	fn test_algorithm() {
		let original =
			KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256, crate::test_provider()).unwrap();
		let key = PrivateKeyDer::try_from(original.serialize_der()).unwrap();
		let key_pair = KeyPair::from_der(&key, crate::test_provider()).unwrap();
		assert_eq!(key_pair.algorithm(), &PKCS_ECDSA_P256_SHA256);
	}
}
