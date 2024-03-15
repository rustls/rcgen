use std::fmt;

#[cfg(feature = "pem")]
use pem::Pem;
#[cfg(feature = "crypto")]
use pki_types::PrivatePkcs8KeyDer;
use yasna::{DERWriter, DERWriterSeq};

#[cfg(any(feature = "crypto", feature = "pem"))]
use crate::error::ExternalError;
#[cfg(all(feature = "crypto", feature = "aws_lc_rs", not(feature = "ring")))]
use crate::ring_like::rsa::KeySize;
#[cfg(feature = "crypto")]
use crate::ring_like::{
	error as ring_error,
	rand::SystemRandom,
	signature::{
		self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as RingKeyPair, RsaEncoding, RsaKeyPair,
	},
	{ecdsa_from_pkcs8, rsa_key_pair_public_modulus_len},
};
#[cfg(feature = "crypto")]
use crate::sign_algo::{algo::*, SignAlgo};
#[cfg(feature = "pem")]
use crate::ENCODE_CONFIG;
use crate::{sign_algo::SignatureAlgorithm, Error};

/// A key pair variant
#[allow(clippy::large_enum_variant)]
pub(crate) enum KeyPairKind {
	/// A Ecdsa key pair
	#[cfg(feature = "crypto")]
	Ec(EcdsaKeyPair),
	/// A Ed25519 key pair
	#[cfg(feature = "crypto")]
	Ed(Ed25519KeyPair),
	/// A RSA key pair
	#[cfg(feature = "crypto")]
	Rsa(RsaKeyPair, &'static dyn RsaEncoding),
	/// A remote key pair
	Remote(Box<dyn RemoteKeyPair + Send + Sync>),
}

impl fmt::Debug for KeyPairKind {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			#[cfg(feature = "crypto")]
			Self::Ec(key_pair) => write!(f, "{:?}", key_pair),
			#[cfg(feature = "crypto")]
			Self::Ed(key_pair) => write!(f, "{:?}", key_pair),
			#[cfg(feature = "crypto")]
			Self::Rsa(key_pair, _) => write!(f, "{:?}", key_pair),
			Self::Remote(_) => write!(f, "Box<dyn RemotePrivateKey>"),
		}
	}
}

/// A key pair used to sign certificates and CSRs
///
/// Note that ring, the underlying library to handle RSA keys
/// requires them to be in a special format, meaning that
/// `openssl genrsa` doesn't work. See ring's [documentation](ring::signature::RsaKeyPair::from_pkcs8)
/// for how to generate RSA keys in the wanted format
/// and conversion between the formats.
#[derive(Debug)]
pub struct KeyPair {
	pub(crate) kind: KeyPairKind,
	pub(crate) alg: &'static SignatureAlgorithm,
	pub(crate) serialized_der: Vec<u8>,
}

impl KeyPair {
	/// Generate a new random [`PKCS_ECDSA_P256_SHA256`] key pair
	#[cfg(feature = "crypto")]
	pub fn generate() -> Result<Self, Error> {
		Self::generate_for(&PKCS_ECDSA_P256_SHA256)
	}

	/// Generate a new random key pair for the specified signature algorithm
	///
	/// If you're not sure which algorithm to use, [`PKCS_ECDSA_P256_SHA256`] is a good choice.
	/// If passed an RSA signature algorithm, it depends on the backend whether we return
	/// a generated key or an error for key generation being unavailable.
	/// Currently, only `aws-lc-rs` supports RSA key generation.
	#[cfg(feature = "crypto")]
	pub fn generate_for(alg: &'static SignatureAlgorithm) -> Result<Self, Error> {
		let rng = &SystemRandom::new();

		match alg.sign_alg {
			SignAlgo::EcDsa(sign_alg) => {
				let key_pair_doc = EcdsaKeyPair::generate_pkcs8(sign_alg, rng)._err()?;
				let key_pair_serialized = key_pair_doc.as_ref().to_vec();

				let key_pair = ecdsa_from_pkcs8(sign_alg, key_pair_doc.as_ref(), rng).unwrap();
				Ok(KeyPair {
					kind: KeyPairKind::Ec(key_pair),
					alg,
					serialized_der: key_pair_serialized,
				})
			},
			SignAlgo::EdDsa(_sign_alg) => {
				let key_pair_doc = Ed25519KeyPair::generate_pkcs8(rng)._err()?;
				let key_pair_serialized = key_pair_doc.as_ref().to_vec();

				let key_pair = Ed25519KeyPair::from_pkcs8(key_pair_doc.as_ref()).unwrap();
				Ok(KeyPair {
					kind: KeyPairKind::Ed(key_pair),
					alg,
					serialized_der: key_pair_serialized,
				})
			},
			#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
			SignAlgo::Rsa(sign_alg) => Self::generate_rsa_inner(alg, sign_alg, KeySize::Rsa2048),
			// Ring doesn't have RSA key generation yet:
			// https://github.com/briansmith/ring/issues/219
			// https://github.com/briansmith/ring/pull/733
			#[cfg(any(not(feature = "aws_lc_rs"), feature = "ring"))]
			SignAlgo::Rsa(_sign_alg) => Err(Error::KeyGenerationUnavailable),
		}
	}

	/// Generates a new random RSA key pair for the specified key size
	///
	/// If passed a signature algorithm that is not RSA, it will return
	/// [`Error::KeyGenerationUnavailable`].
	#[cfg(all(feature = "crypto", feature = "aws_lc_rs", not(feature = "ring")))]
	pub fn generate_rsa_for(
		alg: &'static SignatureAlgorithm,
		key_size: RsaKeySize,
	) -> Result<Self, Error> {
		match alg.sign_alg {
			SignAlgo::Rsa(sign_alg) => {
				let key_size = match key_size {
					RsaKeySize::_2048 => KeySize::Rsa2048,
					RsaKeySize::_3072 => KeySize::Rsa3072,
					RsaKeySize::_4096 => KeySize::Rsa4096,
				};
				Self::generate_rsa_inner(alg, sign_alg, key_size)
			},
			_ => Err(Error::KeyGenerationUnavailable),
		}
	}

	#[cfg(all(feature = "crypto", feature = "aws_lc_rs", not(feature = "ring")))]
	fn generate_rsa_inner(
		alg: &'static SignatureAlgorithm,
		sign_alg: &'static dyn RsaEncoding,
		key_size: KeySize,
	) -> Result<Self, Error> {
		use aws_lc_rs::encoding::AsDer;
		let key_pair = RsaKeyPair::generate(key_size)._err()?;
		let key_pair_serialized = key_pair.as_der()._err()?.as_ref().to_vec();

		Ok(KeyPair {
			kind: KeyPairKind::Rsa(key_pair, sign_alg),
			alg,
			serialized_der: key_pair_serialized,
		})
	}

	/// Parses the key pair from the DER format
	///
	/// Equivalent to using the [`TryFrom`] implementation.
	///
	/// You can use [`rustls_pemfile::private_key`] to get the `der` input. If
	/// you have already a byte slice, just calling `into()` and taking a reference
	/// will convert it to a [`PrivatePkcs8KeyDer`].
	///
	/// [`rustls_pemfile::private_key`]: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/fn.private_key.html
	#[cfg(feature = "crypto")]
	pub fn from_der(der: &PrivatePkcs8KeyDer<'_>) -> Result<Self, Error> {
		der.try_into()
	}

	/// Returns the key pair's signature algorithm
	pub fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.alg
	}

	/// Parses the key pair from the ASCII PEM format
	///
	/// The key must be a DER-encoded plaintext private key; as specified in PKCS #8/RFC 5958;
	///
	/// Appears as "PRIVATE KEY" in PEM files.
	#[cfg(all(feature = "pem", feature = "crypto"))]
	pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
		let private_key = pem::parse(pem_str)._err()?;
		let private_key_der: &[_] = private_key.contents();
		Self::from_der(&private_key_der.into())
	}

	/// Obtains the key pair from a raw public key and a remote private key
	pub fn from_remote(key_pair: Box<dyn RemoteKeyPair + Send + Sync>) -> Result<Self, Error> {
		Ok(Self {
			alg: key_pair.algorithm(),
			kind: KeyPairKind::Remote(key_pair),
			serialized_der: Vec::new(),
		})
	}

	/// Obtains the key pair from a DER formatted key
	/// using the specified [`SignatureAlgorithm`]
	///
	/// The key must be a DER-encoded plaintext private key; as specified in PKCS #8/RFC 5958;
	///
	/// Appears as "PRIVATE KEY" in PEM files
	/// Same as [from_pem_and_sign_algo](Self::from_pem_and_sign_algo).
	#[cfg(all(feature = "pem", feature = "crypto"))]
	pub fn from_pem_and_sign_algo(
		pem_str: &str,
		alg: &'static SignatureAlgorithm,
	) -> Result<Self, Error> {
		let private_key = pem::parse(pem_str)._err()?;
		let private_key_der: &[_] = private_key.contents();
		Self::from_der_and_sign_algo(&PrivatePkcs8KeyDer::from(private_key_der), alg)
	}

	/// Obtains the key pair from a DER formatted key
	/// using the specified [`SignatureAlgorithm`]
	///
	/// Usually, calling this function is not neccessary and you can just call
	/// [`from_der`](Self::from_der) instead. That function will try to figure
	/// out a fitting [`SignatureAlgorithm`] for the given
	/// key pair. However, sometimes multiple signature algorithms fit for the
	/// same der key. In that instance, you can use this function to precisely
	/// specify the `SignatureAlgorithm`.
	///
	/// You can use [`rustls_pemfile::private_key`] to get the `pkcs8` input. If
	/// you have already a byte slice, just calling `into()` and taking a reference
	/// will convert it to a [`PrivatePkcs8KeyDer`].
	///
	/// [`rustls_pemfile::private_key`]: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/fn.private_key.html
	#[cfg(feature = "crypto")]
	pub fn from_der_and_sign_algo(
		pkcs8: &PrivatePkcs8KeyDer<'_>,
		alg: &'static SignatureAlgorithm,
	) -> Result<Self, Error> {
		let rng = &SystemRandom::new();
		let serialized_der = pkcs8.secret_pkcs8_der().to_vec();

		let kind = if alg == &PKCS_ED25519 {
			KeyPairKind::Ed(Ed25519KeyPair::from_pkcs8_maybe_unchecked(&serialized_der)._err()?)
		} else if alg == &PKCS_ECDSA_P256_SHA256 {
			KeyPairKind::Ec(ecdsa_from_pkcs8(
				&signature::ECDSA_P256_SHA256_ASN1_SIGNING,
				&serialized_der,
				rng,
			)?)
		} else if alg == &PKCS_ECDSA_P384_SHA384 {
			KeyPairKind::Ec(ecdsa_from_pkcs8(
				&signature::ECDSA_P384_SHA384_ASN1_SIGNING,
				&serialized_der,
				rng,
			)?)
		} else if alg == &PKCS_RSA_SHA256 {
			let rsakp = RsaKeyPair::from_pkcs8(&serialized_der)._err()?;
			KeyPairKind::Rsa(rsakp, &signature::RSA_PKCS1_SHA256)
		} else if alg == &PKCS_RSA_SHA384 {
			let rsakp = RsaKeyPair::from_pkcs8(&serialized_der)._err()?;
			KeyPairKind::Rsa(rsakp, &signature::RSA_PKCS1_SHA384)
		} else if alg == &PKCS_RSA_SHA512 {
			let rsakp = RsaKeyPair::from_pkcs8(&serialized_der)._err()?;
			KeyPairKind::Rsa(rsakp, &signature::RSA_PKCS1_SHA512)
		} else if alg == &PKCS_RSA_PSS_SHA256 {
			let rsakp = RsaKeyPair::from_pkcs8(&serialized_der)._err()?;
			KeyPairKind::Rsa(rsakp, &signature::RSA_PSS_SHA256)
		} else {
			panic!("Unknown SignatureAlgorithm specified!");
		};

		Ok(KeyPair {
			kind,
			alg,
			serialized_der,
		})
	}

	/// Parses the key pair from the DER format
	///
	/// You can use [`rustls_pemfile::private_key`] to get the `pkcs8` input. If
	/// you have already a byte slice, just calling `into()` and taking a reference
	/// will convert it to a [`PrivatePkcs8KeyDer`].
	///
	/// [`rustls_pemfile::private_key`]: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/fn.private_key.html
	#[cfg(feature = "crypto")]
	pub(crate) fn from_raw(
		pkcs8: &PrivatePkcs8KeyDer,
	) -> Result<(KeyPairKind, &'static SignatureAlgorithm), Error> {
		let pkcs8 = pkcs8.secret_pkcs8_der();
		let rng = SystemRandom::new();
		let (kind, alg) = if let Ok(edkp) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8) {
			(KeyPairKind::Ed(edkp), &PKCS_ED25519)
		} else if let Ok(eckp) =
			ecdsa_from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
		{
			(KeyPairKind::Ec(eckp), &PKCS_ECDSA_P256_SHA256)
		} else if let Ok(eckp) =
			ecdsa_from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8, &rng)
		{
			(KeyPairKind::Ec(eckp), &PKCS_ECDSA_P384_SHA384)
		} else if let Ok(rsakp) = RsaKeyPair::from_pkcs8(pkcs8) {
			(
				KeyPairKind::Rsa(rsakp, &signature::RSA_PKCS1_SHA256),
				&PKCS_RSA_SHA256,
			)
		} else {
			return Err(Error::CouldNotParseKeyPair);
		};
		Ok((kind, alg))
	}

	/// Get the raw public key of this key pair
	///
	/// The key is in raw format, as how [`ring::signature::KeyPair::public_key`]
	/// would output, and how [`ring::signature::UnparsedPublicKey::verify`]
	/// would accept.
	pub fn public_key_raw(&self) -> &[u8] {
		self.raw_bytes()
	}

	/// Check if this key pair can be used with the given signature algorithm
	pub fn is_compatible(&self, signature_algorithm: &SignatureAlgorithm) -> bool {
		self.alg == signature_algorithm
	}

	/// Returns (possibly multiple) compatible [`SignatureAlgorithm`]'s
	/// that the key can be used with
	pub fn compatible_algs(&self) -> impl Iterator<Item = &'static SignatureAlgorithm> {
		std::iter::once(self.alg)
	}

	pub(crate) fn sign_der(
		&self,
		f: impl FnOnce(&mut DERWriterSeq<'_>) -> Result<(), Error>,
	) -> Result<Vec<u8>, Error> {
		yasna::try_construct_der(|writer| {
			writer.write_sequence(|writer| {
				let data = yasna::try_construct_der(|writer| writer.write_sequence(f))?;
				writer.next().write_der(&data);

				// Write signatureAlgorithm
				self.alg.write_alg_ident(writer.next());

				// Write signature
				self.sign(&data, writer.next())?;

				Ok(())
			})
		})
	}

	pub(crate) fn sign(&self, msg: &[u8], writer: DERWriter) -> Result<(), Error> {
		match &self.kind {
			#[cfg(feature = "crypto")]
			KeyPairKind::Ec(kp) => {
				let system_random = SystemRandom::new();
				let signature = kp.sign(&system_random, msg)._err()?;
				let sig = &signature.as_ref();
				writer.write_bitvec_bytes(sig, &sig.len() * 8);
			},
			#[cfg(feature = "crypto")]
			KeyPairKind::Ed(kp) => {
				let signature = kp.sign(msg);
				let sig = &signature.as_ref();
				writer.write_bitvec_bytes(sig, &sig.len() * 8);
			},
			#[cfg(feature = "crypto")]
			KeyPairKind::Rsa(kp, padding_alg) => {
				let system_random = SystemRandom::new();
				let mut signature = vec![0; rsa_key_pair_public_modulus_len(kp)];
				kp.sign(*padding_alg, &system_random, msg, &mut signature)
					._err()?;
				let sig = &signature.as_ref();
				writer.write_bitvec_bytes(sig, &sig.len() * 8);
			},
			KeyPairKind::Remote(kp) => {
				let signature = kp.sign(msg)?;
				writer.write_bitvec_bytes(&signature, &signature.len() * 8);
			},
		}
		Ok(())
	}

	/// Return the key pair's public key in DER format
	///
	/// The key is formatted according to the SubjectPublicKeyInfo struct of
	/// X.509.
	/// See [RFC 5280 section 4.1](https://tools.ietf.org/html/rfc5280#section-4.1).
	pub fn public_key_der(&self) -> Vec<u8> {
		yasna::construct_der(|writer| self.serialize_public_key_der(writer))
	}

	/// Return the key pair's public key in PEM format
	///
	/// The returned string can be interpreted with `openssl pkey --inform PEM -pubout -pubin -text`
	#[cfg(feature = "pem")]
	pub fn public_key_pem(&self) -> String {
		let contents = self.public_key_der();
		let p = Pem::new("PUBLIC KEY", contents);
		pem::encode_config(&p, ENCODE_CONFIG)
	}

	/// Serializes the key pair (including the private key) in PKCS#8 format in DER
	///
	/// Panics if called on a remote key pair.
	pub fn serialize_der(&self) -> Vec<u8> {
		#[cfg_attr(not(feature = "crypto"), allow(irrefutable_let_patterns))]
		if let KeyPairKind::Remote(_) = self.kind {
			panic!("Serializing a remote key pair is not supported")
		}

		self.serialized_der.clone()
	}

	/// Returns a reference to the serialized key pair (including the private key)
	/// in PKCS#8 format in DER
	///
	/// Panics if called on a remote key pair.
	pub fn serialized_der(&self) -> &[u8] {
		#[cfg_attr(not(feature = "crypto"), allow(irrefutable_let_patterns))]
		if let KeyPairKind::Remote(_) = self.kind {
			panic!("Serializing a remote key pair is not supported")
		}

		&self.serialized_der
	}

	/// Access the remote key pair if it is a remote one
	pub fn as_remote(&self) -> Option<&(dyn RemoteKeyPair + Send + Sync)> {
		#[cfg_attr(not(feature = "crypto"), allow(irrefutable_let_patterns))]
		if let KeyPairKind::Remote(remote) = &self.kind {
			Some(remote.as_ref())
		} else {
			None
		}
	}

	/// Serializes the key pair (including the private key) in PKCS#8 format in PEM
	#[cfg(feature = "pem")]
	pub fn serialize_pem(&self) -> String {
		let contents = self.serialize_der();
		let p = Pem::new("PRIVATE KEY", contents);
		pem::encode_config(&p, ENCODE_CONFIG)
	}
}

#[cfg(feature = "crypto")]
impl TryFrom<&[u8]> for KeyPair {
	type Error = Error;

	fn try_from(pkcs8: &[u8]) -> Result<KeyPair, Error> {
		let (kind, alg) = KeyPair::from_raw(&pkcs8.into())?;
		Ok(KeyPair {
			kind,
			alg,
			serialized_der: pkcs8.to_vec(),
		})
	}
}

#[cfg(feature = "crypto")]
impl TryFrom<Vec<u8>> for KeyPair {
	type Error = Error;

	fn try_from(pkcs8: Vec<u8>) -> Result<KeyPair, Error> {
		let (kind, alg) = KeyPair::from_raw(&pkcs8.as_slice().into())?;
		Ok(KeyPair {
			kind,
			alg,
			serialized_der: pkcs8,
		})
	}
}

#[cfg(feature = "crypto")]
impl TryFrom<&PrivatePkcs8KeyDer<'_>> for KeyPair {
	type Error = Error;

	fn try_from(pkcs8: &PrivatePkcs8KeyDer) -> Result<KeyPair, Error> {
		let (kind, alg) = KeyPair::from_raw(pkcs8)?;
		Ok(KeyPair {
			kind,
			alg,
			serialized_der: pkcs8.secret_pkcs8_der().into(),
		})
	}
}

/// The key size used for RSA key generation
#[cfg(all(feature = "crypto", feature = "aws_lc_rs", not(feature = "ring")))]
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

impl PublicKeyData for KeyPair {
	fn alg(&self) -> &SignatureAlgorithm {
		self.alg
	}
	fn raw_bytes(&self) -> &[u8] {
		match &self.kind {
			#[cfg(feature = "crypto")]
			KeyPairKind::Ec(kp) => kp.public_key().as_ref(),
			#[cfg(feature = "crypto")]
			KeyPairKind::Ed(kp) => kp.public_key().as_ref(),
			#[cfg(feature = "crypto")]
			KeyPairKind::Rsa(kp, _) => kp.public_key().as_ref(),
			KeyPairKind::Remote(kp) => kp.public_key(),
		}
	}
}

/// A private key that is not directly accessible, but can be used to sign messages
///
/// Trait objects based on this trait can be passed to the [`KeyPair::from_remote`] function for generating certificates
/// from a remote and raw private key, for example an HSM.
pub trait RemoteKeyPair {
	/// Returns the public key of this key pair in the binary format as in [`KeyPair::public_key_raw`]
	fn public_key(&self) -> &[u8];

	/// Signs `msg` using the selected algorithm
	fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error>;

	/// Reveals the algorithm to be used when calling `sign()`
	fn algorithm(&self) -> &'static SignatureAlgorithm;
}

#[cfg(feature = "crypto")]
impl<T> ExternalError<T> for Result<T, ring_error::KeyRejected> {
	fn _err(self) -> Result<T, Error> {
		self.map_err(|e| Error::RingKeyRejected(e.to_string()))
	}
}

#[cfg(feature = "crypto")]
impl<T> ExternalError<T> for Result<T, ring_error::Unspecified> {
	fn _err(self) -> Result<T, Error> {
		self.map_err(|_| Error::RingUnspecified)
	}
}

#[cfg(feature = "pem")]
impl<T> ExternalError<T> for Result<T, pem::PemError> {
	fn _err(self) -> Result<T, Error> {
		self.map_err(|e| Error::PemError(e.to_string()))
	}
}

pub(crate) trait PublicKeyData {
	fn alg(&self) -> &SignatureAlgorithm;

	fn raw_bytes(&self) -> &[u8];

	fn serialize_public_key_der(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			self.alg().write_oids_sign_alg(writer.next());
			let pk = self.raw_bytes();
			writer.next().write_bitvec_bytes(pk, pk.len() * 8);
		})
	}
}

#[cfg(test)]
mod test {
	#[cfg(crypto)]
	use super::*;

	#[cfg(crypto)]
	use crate::ring_like::{
		rand::SystemRandom,
		signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
	};

	#[cfg(crypto)]
	#[test]
	fn test_algorithm() {
		let rng = SystemRandom::new();
		let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
		let der = pkcs8.as_ref().to_vec();

		let key_pair = KeyPair::from_der(&der).unwrap();
		assert_eq!(key_pair.algorithm(), &PKCS_ECDSA_P256_SHA256);
	}
}
