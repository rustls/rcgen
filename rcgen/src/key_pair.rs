#[cfg(feature = "crypto")]
use std::fmt;

#[cfg(feature = "pem")]
use pem::Pem;
#[cfg(feature = "crypto")]
use pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use yasna::{DERWriter, DERWriterSeq};

#[cfg(feature = "crypto")]
use crate::crypto::CryptoProvider;
#[cfg(feature = "pem")]
use crate::error::ExternalError;
#[cfg(feature = "crypto")]
use crate::sign_algo::algo::*;
use crate::sign_algo::SignatureAlgorithm;
use crate::Error;
#[cfg(feature = "pem")]
use crate::ENCODE_CONFIG;

/// A key pair used to sign certificates and CSRs.
///
/// `KeyPair` is independent of a concrete cryptography library. Its implementation is created by
/// the selected [`CryptoProvider`], while this type retains the stable rcgen API and exportable
/// private-key bytes.
#[cfg(feature = "crypto")]
pub struct KeyPair {
	pub(crate) signing_key: Box<dyn SigningKey + Send + Sync>,
	pub(crate) serialized_der: Vec<u8>,
}

#[cfg(feature = "crypto")]
impl fmt::Debug for KeyPair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("KeyPair")
			.field("alg", &self.algorithm())
			.field("serialized_der", &"[secret key elided]")
			.finish()
	}
}

#[cfg(feature = "crypto")]
impl KeyPair {
	/// Construct a key pair from a provider-specific signing key and its PKCS#8 DER encoding.
	///
	/// This constructor is intended for implementations of
	/// [`KeyPairProvider`](crate::crypto::KeyPairProvider). `serialized_der` must encode the same
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

	/// Generate a new random [`PKCS_ECDSA_P256_SHA256`] key pair.
	pub fn generate() -> Result<Self, Error> {
		Self::generate_for(&PKCS_ECDSA_P256_SHA256)
	}

	/// Generate a new random [`PKCS_ECDSA_P256_SHA256`] key pair with `provider`.
	pub fn generate_with_provider(provider: &CryptoProvider) -> Result<Self, Error> {
		Self::generate_for_with_provider(&PKCS_ECDSA_P256_SHA256, provider)
	}

	/// Generate a new random key pair for the specified signature algorithm.
	///
	/// If no process-wide provider has been installed, a built-in provider is selected only when
	/// a built-in backend feature is enabled. AWS-LC takes precedence if both are enabled.
	pub fn generate_for(alg: &'static SignatureAlgorithm) -> Result<Self, Error> {
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::generate_for_with_provider(alg, provider)
	}

	/// Generate a new random key pair using `provider`.
	pub fn generate_for_with_provider(
		alg: &'static SignatureAlgorithm,
		provider: &CryptoProvider,
	) -> Result<Self, Error> {
		provider.key_pair_provider.generate(alg)
	}

	/// Generate a new random RSA key pair for the specified key size.
	pub fn generate_rsa_for(
		alg: &'static SignatureAlgorithm,
		key_size: RsaKeySize,
	) -> Result<Self, Error> {
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::generate_rsa_for_with_provider(alg, key_size, provider)
	}

	/// Generate a new random RSA key pair of `key_size` using `provider`.
	pub fn generate_rsa_for_with_provider(
		alg: &'static SignatureAlgorithm,
		key_size: RsaKeySize,
		provider: &CryptoProvider,
	) -> Result<Self, Error> {
		provider.key_pair_provider.generate_rsa(alg, key_size)
	}

	/// Returns the key pair's signature algorithm.
	pub fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.signing_key.algorithm()
	}

	/// Parse a key pair from ASCII PEM using the process-wide provider.
	#[cfg(feature = "pem")]
	pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::from_pem_with_provider(pem_str, provider)
	}

	/// Parse a key pair from ASCII PEM using `provider`.
	#[cfg(feature = "pem")]
	pub fn from_pem_with_provider(pem_str: &str, provider: &CryptoProvider) -> Result<Self, Error> {
		let private_key = pem::parse(pem_str)._err()?;
		let private_key = PrivateKeyDer::try_from(private_key.into_contents())
			.map_err(|_| Error::CouldNotParseKeyPair)?;
		Self::from_der_with_provider(&private_key, provider)
	}

	/// Parse a PKCS#8 PEM key for a specified signature algorithm.
	#[cfg(feature = "pem")]
	pub fn from_pkcs8_pem_and_sign_algo(
		pem_str: &str,
		alg: &'static SignatureAlgorithm,
	) -> Result<Self, Error> {
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::from_pkcs8_pem_and_sign_algo_with_provider(pem_str, alg, provider)
	}

	/// Parse a PKCS#8 PEM key for `alg` using `provider`.
	#[cfg(feature = "pem")]
	pub fn from_pkcs8_pem_and_sign_algo_with_provider(
		pem_str: &str,
		alg: &'static SignatureAlgorithm,
		provider: &CryptoProvider,
	) -> Result<Self, Error> {
		let private_key = pem::parse(pem_str)._err()?;
		let private_key = PrivatePkcs8KeyDer::from(private_key.into_contents());
		Self::from_pkcs8_der_and_sign_algo_with_provider(&private_key, alg, provider)
	}

	/// Parse a PKCS#8 DER key for a specified signature algorithm.
	pub fn from_pkcs8_der_and_sign_algo(
		pkcs8: &PrivatePkcs8KeyDer<'_>,
		alg: &'static SignatureAlgorithm,
	) -> Result<Self, Error> {
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::from_pkcs8_der_and_sign_algo_with_provider(pkcs8, alg, provider)
	}

	/// Parse a PKCS#8 DER key for `alg` using `provider`.
	pub fn from_pkcs8_der_and_sign_algo_with_provider(
		pkcs8: &PrivatePkcs8KeyDer<'_>,
		alg: &'static SignatureAlgorithm,
		provider: &CryptoProvider,
	) -> Result<Self, Error> {
		provider
			.key_pair_provider
			.load_private_key(PrivateKeyDer::Pkcs8(pkcs8.clone_key()), Some(alg))
	}

	/// Parse a PEM key for a specified signature algorithm.
	#[cfg(feature = "pem")]
	pub fn from_pem_and_sign_algo(
		pem_str: &str,
		alg: &'static SignatureAlgorithm,
	) -> Result<Self, Error> {
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::from_pem_and_sign_algo_with_provider(pem_str, alg, provider)
	}

	/// Parse a PEM key for `alg` using `provider`.
	#[cfg(feature = "pem")]
	pub fn from_pem_and_sign_algo_with_provider(
		pem_str: &str,
		alg: &'static SignatureAlgorithm,
		provider: &CryptoProvider,
	) -> Result<Self, Error> {
		let private_key = pem::parse(pem_str)._err()?;
		let private_key = PrivateKeyDer::try_from(private_key.into_contents())
			.map_err(|_| Error::CouldNotParseKeyPair)?;
		Self::from_der_and_sign_algo_with_provider(&private_key, alg, provider)
	}

	/// Parse a DER key for a specified signature algorithm.
	pub fn from_der_and_sign_algo(
		key: &PrivateKeyDer<'_>,
		alg: &'static SignatureAlgorithm,
	) -> Result<Self, Error> {
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::from_der_and_sign_algo_with_provider(key, alg, provider)
	}

	/// Parse a DER key for `alg` using `provider`.
	pub fn from_der_and_sign_algo_with_provider(
		key: &PrivateKeyDer<'_>,
		alg: &'static SignatureAlgorithm,
		provider: &CryptoProvider,
	) -> Result<Self, Error> {
		provider
			.key_pair_provider
			.load_private_key(key.clone_key(), Some(alg))
	}

	/// Parse a DER key and let `provider` detect its signature algorithm.
	pub fn from_der_with_provider(
		key: &PrivateKeyDer<'_>,
		provider: &CryptoProvider,
	) -> Result<Self, Error> {
		provider
			.key_pair_provider
			.load_private_key(key.clone_key(), None)
	}

	/// Get the raw public key of this key pair.
	pub fn public_key_raw(&self) -> &[u8] {
		self.der_bytes()
	}

	/// Check if this key pair can be used with the given signature algorithm.
	pub fn is_compatible(&self, signature_algorithm: &SignatureAlgorithm) -> bool {
		self.algorithm() == signature_algorithm
	}

	/// Return the compatible [`SignatureAlgorithm`] for this key pair.
	pub fn compatible_algs(&self) -> impl Iterator<Item = &'static SignatureAlgorithm> {
		std::iter::once(self.algorithm())
	}

	/// Return the key pair's public key in PEM format.
	#[cfg(feature = "pem")]
	pub fn public_key_pem(&self) -> String {
		let contents = self.subject_public_key_info();
		let p = Pem::new("PUBLIC KEY", contents);
		pem::encode_config(&p, ENCODE_CONFIG)
	}

	/// Serialize the key pair, including its private key, as PKCS#8 DER.
	pub fn serialize_der(&self) -> Vec<u8> {
		self.serialized_der.clone()
	}

	/// Borrow the serialized key pair, including its private key, as PKCS#8 DER.
	pub fn serialized_der(&self) -> &[u8] {
		&self.serialized_der
	}

	/// Serialize the key pair, including its private key, as PKCS#8 PEM.
	#[cfg(feature = "pem")]
	pub fn serialize_pem(&self) -> String {
		let p = Pem::new("PRIVATE KEY", self.serialize_der());
		pem::encode_config(&p, ENCODE_CONFIG)
	}
}

#[cfg(feature = "crypto")]
impl SigningKey for KeyPair {
	fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
		self.signing_key.sign(msg)
	}
}

#[cfg(feature = "crypto")]
impl PublicKeyData for KeyPair {
	fn der_bytes(&self) -> &[u8] {
		self.signing_key.der_bytes()
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.signing_key.algorithm()
	}
}

#[cfg(feature = "crypto")]
impl TryFrom<&[u8]> for KeyPair {
	type Error = Error;

	fn try_from(key: &[u8]) -> Result<Self, Error> {
		let key = PrivateKeyDer::try_from(key).map_err(|_| Error::CouldNotParseKeyPair)?;
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::from_der_with_provider(&key, provider)
	}
}

#[cfg(feature = "crypto")]
impl TryFrom<Vec<u8>> for KeyPair {
	type Error = Error;

	fn try_from(key: Vec<u8>) -> Result<Self, Error> {
		let key = PrivateKeyDer::try_from(key).map_err(|_| Error::CouldNotParseKeyPair)?;
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::from_der_with_provider(&key, provider)
	}
}

#[cfg(feature = "crypto")]
impl TryFrom<&PrivatePkcs8KeyDer<'_>> for KeyPair {
	type Error = Error;

	fn try_from(key: &PrivatePkcs8KeyDer<'_>) -> Result<Self, Error> {
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		provider
			.key_pair_provider
			.load_private_key(PrivateKeyDer::Pkcs8(key.clone_key()), None)
	}
}

#[cfg(feature = "crypto")]
impl TryFrom<&PrivateKeyDer<'_>> for KeyPair {
	type Error = Error;

	fn try_from(key: &PrivateKeyDer<'_>) -> Result<Self, Error> {
		let provider = CryptoProvider::get_default_or_install_from_crate_features()?;
		Self::from_der_with_provider(key, provider)
	}
}

#[cfg(feature = "crypto")]
impl From<KeyPair> for PrivatePkcs8KeyDer<'static> {
	fn from(val: KeyPair) -> Self {
		val.serialize_der().into()
	}
}

#[cfg(feature = "crypto")]
impl From<KeyPair> for PrivateKeyDer<'static> {
	fn from(val: KeyPair) -> Self {
		Self::from(PrivatePkcs8KeyDer::from(val))
	}
}

/// The key size used for RSA key generation.
#[cfg(feature = "crypto")]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RsaKeySize {
	/// 2048 bits.
	_2048,
	/// 3072 bits.
	_3072,
	/// 4096 bits.
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

			key.algorithm().write_alg_ident(writer.next());

			let sig = key.sign(&data)?;
			writer.next().write_bitvec_bytes(&sig, sig.len() * 8);

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

/// A key that can be used to sign messages.
pub trait SigningKey: PublicKeyData {
	/// Sign `msg` using the selected algorithm.
	fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error>;
}

#[cfg(feature = "pem")]
impl<T> ExternalError<T> for Result<T, pem::PemError> {
	fn _err(self) -> Result<T, Error> {
		self.map_err(|e| Error::PemError(e.to_string()))
	}
}

/// A public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
	pub(crate) alg: &'static SignatureAlgorithm,
	pub(crate) subject_public_key: Vec<u8>,
}

impl SubjectPublicKeyInfo {
	/// Create a `SubjectPublicKeyInfo` value from PEM.
	#[cfg(all(feature = "x509-parser", feature = "pem"))]
	pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
		Self::from_der(&pem::parse(pem_str)._err()?.into_contents())
	}

	/// Create a `SubjectPublicKeyInfo` value from DER.
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

/// The public key data of a key pair.
pub trait PublicKeyData {
	/// Return the public key as a DER-encoded SubjectPublicKeyInfo structure.
	fn subject_public_key_info(&self) -> Vec<u8> {
		yasna::construct_der(|writer| serialize_public_key_der(self, writer))
	}

	/// Return the contents of the SubjectPublicKeyInfo `subjectPublicKey` BIT STRING.
	fn der_bytes(&self) -> &[u8];

	/// Return the algorithm used by the key pair.
	fn algorithm(&self) -> &'static SignatureAlgorithm;
}

pub(crate) fn serialize_public_key_der(key: &(impl PublicKeyData + ?Sized), writer: DERWriter) {
	writer.write_sequence(|writer| {
		key.algorithm().write_oids_sign_alg(writer.next());
		let pk = key.der_bytes();
		writer.next().write_bitvec_bytes(pk, pk.len() * 8);
	})
}

#[cfg(all(
	test,
	feature = "crypto",
	any(feature = "ring", feature = "aws_lc_rs", feature = "fips")
))]
mod test {
	use super::*;

	#[cfg(all(feature = "x509-parser", feature = "pem"))]
	#[test]
	fn test_subject_public_key_parsing() {
		for alg in [
			&PKCS_ED25519,
			&PKCS_ECDSA_P256_SHA256,
			&PKCS_ECDSA_P384_SHA384,
			#[cfg(all(any(feature = "aws_lc_rs", feature = "fips"), not(feature = "ring")))]
			&PKCS_ECDSA_P521_SHA512,
			#[cfg(all(any(feature = "aws_lc_rs", feature = "fips"), not(feature = "ring")))]
			&PKCS_RSA_SHA256,
		] {
			let kp = KeyPair::generate_for(alg).expect("keygen");
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
		let original = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
		let key_pair = KeyPair::try_from(original.serialize_der()).unwrap();
		assert_eq!(key_pair.algorithm(), &PKCS_ECDSA_P256_SHA256);
	}
}
