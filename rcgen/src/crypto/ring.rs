//! The built-in `ring` cryptography provider.

use ::ring::digest;
use ::ring::rand::SystemRandom;
use ::ring::signature::{
	self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RsaEncoding, RsaKeyPair,
	VerificationAlgorithm,
};
use pki_types::PrivateKeyDer;

use super::{CryptoProvider, HashAlgorithm, HashOutput};
use crate::{
	Error, KeyPair, PublicKeyData, RsaKeySize, SignatureAlgorithm, SigningKey,
	PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256, PKCS_RSA_SHA384,
	PKCS_RSA_SHA512,
};

/// Return rcgen's built-in `ring` provider.
pub fn default_provider() -> &'static dyn CryptoProvider {
	&RingProvider
}

#[derive(Debug)]
struct RingProvider;

impl RingProvider {
	fn ecdsa_from_pkcs8(
		algorithm: &'static signature::EcdsaSigningAlgorithm,
		pkcs8: &[u8],
	) -> Result<EcdsaKeyPair, Error> {
		EcdsaKeyPair::from_pkcs8(algorithm, pkcs8, &SystemRandom::new())
			.map_err(|e| Error::RingKeyRejected(e.to_string()))
	}

	fn load_with_algorithm(
		&self,
		pkcs8: &[u8],
		algorithm: &'static SignatureAlgorithm,
	) -> Result<RingSigningKey, Error> {
		let kind = if algorithm == &PKCS_ED25519 {
			RingKeyKind::Ed(
				Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8)
					.map_err(|e| Error::RingKeyRejected(e.to_string()))?,
			)
		} else if algorithm == &PKCS_ECDSA_P256_SHA256 {
			RingKeyKind::Ec(Self::ecdsa_from_pkcs8(
				&signature::ECDSA_P256_SHA256_ASN1_SIGNING,
				pkcs8,
			)?)
		} else if algorithm == &PKCS_ECDSA_P384_SHA384 {
			RingKeyKind::Ec(Self::ecdsa_from_pkcs8(
				&signature::ECDSA_P384_SHA384_ASN1_SIGNING,
				pkcs8,
			)?)
		} else if algorithm == &PKCS_RSA_SHA256 {
			RingKeyKind::Rsa(
				RsaKeyPair::from_pkcs8(pkcs8).map_err(|e| Error::RingKeyRejected(e.to_string()))?,
				&signature::RSA_PKCS1_SHA256,
			)
		} else if algorithm == &PKCS_RSA_SHA384 {
			RingKeyKind::Rsa(
				RsaKeyPair::from_pkcs8(pkcs8).map_err(|e| Error::RingKeyRejected(e.to_string()))?,
				&signature::RSA_PKCS1_SHA384,
			)
		} else if algorithm == &PKCS_RSA_SHA512 {
			RingKeyKind::Rsa(
				RsaKeyPair::from_pkcs8(pkcs8).map_err(|e| Error::RingKeyRejected(e.to_string()))?,
				&signature::RSA_PKCS1_SHA512,
			)
		} else {
			return Err(Error::UnsupportedSignatureAlgorithm);
		};

		Ok(RingSigningKey { kind, algorithm })
	}

	fn detect(&self, pkcs8: &[u8]) -> Result<RingSigningKey, Error> {
		for algorithm in [
			&PKCS_ED25519,
			&PKCS_ECDSA_P256_SHA256,
			&PKCS_ECDSA_P384_SHA384,
			&PKCS_RSA_SHA256,
		] {
			if let Ok(key) = self.load_with_algorithm(pkcs8, algorithm) {
				return Ok(key);
			}
		}
		Err(Error::CouldNotParseKeyPair)
	}
}

impl CryptoProvider for RingProvider {
	fn hash(&self, algorithm: HashAlgorithm, input: &[u8]) -> HashOutput {
		let algorithm = match algorithm {
			HashAlgorithm::Sha256 => &digest::SHA256,
			HashAlgorithm::Sha384 => &digest::SHA384,
			HashAlgorithm::Sha512 => &digest::SHA512,
		};
		HashOutput::new(digest::digest(algorithm, input).as_ref())
	}

	fn generate(
		&self,
		algorithm: &'static SignatureAlgorithm,
		key_size: Option<RsaKeySize>,
	) -> Result<KeyPair, Error> {
		if key_size.is_some() {
			return Err(Error::KeyGenerationUnavailable);
		}
		let rng = SystemRandom::new();
		let (signing_key, serialized_der) = if algorithm == &PKCS_ECDSA_P256_SHA256 {
			let document =
				EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
					.map_err(|_| Error::RingUnspecified)?;
			(
				self.load_with_algorithm(document.as_ref(), algorithm)?,
				document.as_ref().to_vec(),
			)
		} else if algorithm == &PKCS_ECDSA_P384_SHA384 {
			let document =
				EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
					.map_err(|_| Error::RingUnspecified)?;
			(
				self.load_with_algorithm(document.as_ref(), algorithm)?,
				document.as_ref().to_vec(),
			)
		} else if algorithm == &PKCS_ED25519 {
			let document =
				Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| Error::RingUnspecified)?;
			(
				self.load_with_algorithm(document.as_ref(), algorithm)?,
				document.as_ref().to_vec(),
			)
		} else if algorithm == &PKCS_RSA_SHA256
			|| algorithm == &PKCS_RSA_SHA384
			|| algorithm == &PKCS_RSA_SHA512
		{
			return Err(Error::KeyGenerationUnavailable);
		} else {
			return Err(Error::UnsupportedSignatureAlgorithm);
		};

		Ok(KeyPair::from_signing_key(
			Box::new(signing_key),
			serialized_der,
		))
	}

	fn load_private_key(
		&self,
		key_der: PrivateKeyDer<'static>,
		algorithm: Option<&'static SignatureAlgorithm>,
	) -> Result<KeyPair, Error> {
		let PrivateKeyDer::Pkcs8(pkcs8) = key_der else {
			return Err(Error::CouldNotParseKeyPair);
		};
		let serialized_der = pkcs8.secret_pkcs8_der().to_vec();
		let signing_key = match algorithm {
			Some(algorithm) => self.load_with_algorithm(&serialized_der, algorithm)?,
			None => self.detect(&serialized_der)?,
		};
		Ok(KeyPair::from_signing_key(
			Box::new(signing_key),
			serialized_der,
		))
	}

	fn verify(
		&self,
		algorithm: &'static SignatureAlgorithm,
		public_key: &[u8],
		message: &[u8],
		signature_bytes: &[u8],
	) -> Result<(), Error> {
		let verification_algorithm: &'static dyn VerificationAlgorithm =
			if algorithm == &PKCS_ECDSA_P256_SHA256 {
				&signature::ECDSA_P256_SHA256_ASN1
			} else if algorithm == &PKCS_ECDSA_P384_SHA384 {
				&signature::ECDSA_P384_SHA384_ASN1
			} else if algorithm == &PKCS_ED25519 {
				&signature::ED25519
			} else if algorithm == &PKCS_RSA_SHA256 {
				&signature::RSA_PKCS1_2048_8192_SHA256
			} else if algorithm == &PKCS_RSA_SHA384 {
				&signature::RSA_PKCS1_2048_8192_SHA384
			} else if algorithm == &PKCS_RSA_SHA512 {
				&signature::RSA_PKCS1_2048_8192_SHA512
			} else {
				return Err(Error::UnsupportedSignatureAlgorithm);
			};

		signature::UnparsedPublicKey::new(verification_algorithm, public_key)
			.verify(message, signature_bytes)
			.map_err(|_| Error::SignatureVerificationFailed)
	}
}

enum RingKeyKind {
	Ec(EcdsaKeyPair),
	Ed(Ed25519KeyPair),
	Rsa(RsaKeyPair, &'static dyn RsaEncoding),
}

struct RingSigningKey {
	kind: RingKeyKind,
	algorithm: &'static SignatureAlgorithm,
}

impl PublicKeyData for RingSigningKey {
	fn der_bytes(&self) -> &[u8] {
		match &self.kind {
			RingKeyKind::Ec(key) => key.public_key().as_ref(),
			RingKeyKind::Ed(key) => key.public_key().as_ref(),
			RingKeyKind::Rsa(key, _) => key.public_key().as_ref(),
		}
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.algorithm
	}
}

impl SigningKey for RingSigningKey {
	fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
		match &self.kind {
			RingKeyKind::Ec(key) => key
				.sign(&SystemRandom::new(), message)
				.map(|signature| signature.as_ref().to_vec())
				.map_err(|_| Error::RingUnspecified),
			RingKeyKind::Ed(key) => Ok(key.sign(message).as_ref().to_vec()),
			RingKeyKind::Rsa(key, encoding) => {
				let mut signature = vec![0; key.public().modulus_len()];
				key.sign(*encoding, &SystemRandom::new(), message, &mut signature)
					.map_err(|_| Error::RingUnspecified)?;
				Ok(signature)
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sha256_known_answer() {
		assert_eq!(
			default_provider()
				.hash(HashAlgorithm::Sha256, b"abc")
				.as_ref(),
			[
				0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
				0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
				0xf2, 0x00, 0x15, 0xad,
			]
		);
	}
}
