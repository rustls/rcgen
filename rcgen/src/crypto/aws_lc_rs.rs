//! The built-in AWS-LC cryptography provider.

use aws_lc_rs::digest;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
	self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RsaEncoding, RsaKeyPair,
	VerificationAlgorithm,
};
#[cfg(feature = "aws_lc_rs")]
use aws_lc_rs::signature::{
	PqdsaKeyPair, PqdsaSigningAlgorithm, ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65,
	ML_DSA_65_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING,
};
use pki_types::PrivateKeyDer;

use super::{
	CryptoProvider, DigestProvider, HashAlgorithm, KeyPairProvider, SignatureVerificationProvider,
};
use crate::{
	Error, KeyPair, PublicKeyData, RsaKeySize, SignatureAlgorithm, SigningKey,
	PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA256, PKCS_ECDSA_P521_SHA384,
	PKCS_ECDSA_P521_SHA512, PKCS_ED25519, PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512,
};
#[cfg(feature = "aws_lc_rs")]
use crate::{PKCS_ML_DSA_44, PKCS_ML_DSA_65, PKCS_ML_DSA_87};

/// Return rcgen's built-in AWS-LC provider.
pub fn default_provider() -> CryptoProvider {
	CryptoProvider {
		key_pair_provider: &AwsLcKeyPairProvider,
		digest_provider: &AwsLcDigestProvider,
		signature_verification_provider: &AwsLcSignatureVerificationProvider,
	}
}

#[derive(Debug)]
struct AwsLcDigestProvider;

impl DigestProvider for AwsLcDigestProvider {
	fn digest(
		&self,
		algorithm: HashAlgorithm,
		input: &[u8],
		output: &mut [u8],
	) -> Result<(), Error> {
		let algorithm = match algorithm {
			HashAlgorithm::Sha256 => &digest::SHA256,
			HashAlgorithm::Sha384 => &digest::SHA384,
			HashAlgorithm::Sha512 => &digest::SHA512,
		};
		output.copy_from_slice(digest::digest(algorithm, input).as_ref());
		Ok(())
	}
}

#[derive(Debug)]
struct AwsLcKeyPairProvider;

impl AwsLcKeyPairProvider {
	fn ecdsa_from_key(
		algorithm: &'static signature::EcdsaSigningAlgorithm,
		key_der: &[u8],
	) -> Result<EcdsaKeyPair, Error> {
		EcdsaKeyPair::from_private_key_der(algorithm, key_der)
			.map_err(|e| Error::RingKeyRejected(e.to_string()))
	}

	fn rsa_from_key(key_der: &[u8], is_pkcs8: bool) -> Result<RsaKeyPair, Error> {
		if is_pkcs8 {
			RsaKeyPair::from_pkcs8(key_der)
		} else {
			RsaKeyPair::from_der(key_der)
		}
		.map_err(|e| Error::RingKeyRejected(e.to_string()))
	}

	fn load_with_algorithm(
		&self,
		key_der: &[u8],
		is_pkcs8: bool,
		algorithm: &'static SignatureAlgorithm,
	) -> Result<AwsLcSigningKey, Error> {
		let kind = if algorithm == &PKCS_ED25519 {
			AwsLcKeyKind::Ed(
				Ed25519KeyPair::from_pkcs8_maybe_unchecked(key_der)
					.map_err(|e| Error::RingKeyRejected(e.to_string()))?,
			)
		} else if algorithm == &PKCS_ECDSA_P256_SHA256 {
			AwsLcKeyKind::Ec(Self::ecdsa_from_key(
				&signature::ECDSA_P256_SHA256_ASN1_SIGNING,
				key_der,
			)?)
		} else if algorithm == &PKCS_ECDSA_P384_SHA384 {
			AwsLcKeyKind::Ec(Self::ecdsa_from_key(
				&signature::ECDSA_P384_SHA384_ASN1_SIGNING,
				key_der,
			)?)
		} else if algorithm == &PKCS_ECDSA_P521_SHA256 {
			AwsLcKeyKind::Ec(Self::ecdsa_from_key(
				&signature::ECDSA_P521_SHA256_ASN1_SIGNING,
				key_der,
			)?)
		} else if algorithm == &PKCS_ECDSA_P521_SHA384 {
			AwsLcKeyKind::Ec(Self::ecdsa_from_key(
				&signature::ECDSA_P521_SHA384_ASN1_SIGNING,
				key_der,
			)?)
		} else if algorithm == &PKCS_ECDSA_P521_SHA512 {
			AwsLcKeyKind::Ec(Self::ecdsa_from_key(
				&signature::ECDSA_P521_SHA512_ASN1_SIGNING,
				key_der,
			)?)
		} else if algorithm == &PKCS_RSA_SHA256 {
			AwsLcKeyKind::Rsa(
				Self::rsa_from_key(key_der, is_pkcs8)?,
				&signature::RSA_PKCS1_SHA256,
			)
		} else if algorithm == &PKCS_RSA_SHA384 {
			AwsLcKeyKind::Rsa(
				Self::rsa_from_key(key_der, is_pkcs8)?,
				&signature::RSA_PKCS1_SHA384,
			)
		} else if algorithm == &PKCS_RSA_SHA512 {
			AwsLcKeyKind::Rsa(
				Self::rsa_from_key(key_der, is_pkcs8)?,
				&signature::RSA_PKCS1_SHA512,
			)
		} else {
			#[cfg(feature = "aws_lc_rs")]
			{
				let signing_algorithm = if algorithm == &PKCS_ML_DSA_44 {
					Some(&ML_DSA_44_SIGNING)
				} else if algorithm == &PKCS_ML_DSA_65 {
					Some(&ML_DSA_65_SIGNING)
				} else if algorithm == &PKCS_ML_DSA_87 {
					Some(&ML_DSA_87_SIGNING)
				} else {
					None
				};
				if let Some(signing_algorithm) = signing_algorithm {
					if !is_pkcs8 {
						return Err(Error::CouldNotParseKeyPair);
					}
					return Ok(AwsLcSigningKey {
						kind: AwsLcKeyKind::Pq(
							PqdsaKeyPair::from_pkcs8(signing_algorithm, key_der)
								.map_err(|e| Error::RingKeyRejected(e.to_string()))?,
						),
						algorithm,
					});
				}
			}
			return Err(Error::UnsupportedSignatureAlgorithm);
		};

		Ok(AwsLcSigningKey { kind, algorithm })
	}

	fn detect(&self, key_der: &[u8], is_pkcs8: bool) -> Result<AwsLcSigningKey, Error> {
		for algorithm in [
			&PKCS_ED25519,
			&PKCS_ECDSA_P256_SHA256,
			&PKCS_ECDSA_P384_SHA384,
			&PKCS_ECDSA_P521_SHA512,
			&PKCS_RSA_SHA256,
			#[cfg(feature = "aws_lc_rs")]
			&PKCS_ML_DSA_44,
			#[cfg(feature = "aws_lc_rs")]
			&PKCS_ML_DSA_65,
			#[cfg(feature = "aws_lc_rs")]
			&PKCS_ML_DSA_87,
		] {
			if let Ok(key) = self.load_with_algorithm(key_der, is_pkcs8, algorithm) {
				return Ok(key);
			}
		}
		Err(Error::CouldNotParseKeyPair)
	}

	fn generate_ecdsa(
		&self,
		algorithm: &'static SignatureAlgorithm,
		signing_algorithm: &'static signature::EcdsaSigningAlgorithm,
	) -> Result<KeyPair, Error> {
		let document = EcdsaKeyPair::generate_pkcs8(signing_algorithm, &SystemRandom::new())
			.map_err(|_| Error::RingUnspecified)?;
		let serialized_der = document.as_ref().to_vec();
		let signing_key = self.load_with_algorithm(&serialized_der, true, algorithm)?;
		Ok(KeyPair::from_signing_key(
			Box::new(signing_key),
			serialized_der,
		))
	}

	fn generate_rsa_inner(
		&self,
		algorithm: &'static SignatureAlgorithm,
		key_size: KeySize,
	) -> Result<KeyPair, Error> {
		if algorithm != &PKCS_RSA_SHA256
			&& algorithm != &PKCS_RSA_SHA384
			&& algorithm != &PKCS_RSA_SHA512
		{
			return Err(Error::KeyGenerationUnavailable);
		}
		let key = RsaKeyPair::generate(key_size).map_err(|_| Error::RingUnspecified)?;
		let serialized_der = key
			.as_der()
			.map_err(|_| Error::RingUnspecified)?
			.as_ref()
			.to_vec();
		let signing_key = self.load_with_algorithm(&serialized_der, true, algorithm)?;
		Ok(KeyPair::from_signing_key(
			Box::new(signing_key),
			serialized_der,
		))
	}

	#[cfg(feature = "aws_lc_rs")]
	fn generate_pqdsa(
		&self,
		algorithm: &'static SignatureAlgorithm,
		signing_algorithm: &'static PqdsaSigningAlgorithm,
	) -> Result<KeyPair, Error> {
		let key = PqdsaKeyPair::generate(signing_algorithm).map_err(|_| Error::RingUnspecified)?;
		let serialized_der = key
			.to_pkcs8v1()
			.map_err(|_| Error::RingUnspecified)?
			.as_ref()
			.to_vec();
		Ok(KeyPair::from_signing_key(
			Box::new(AwsLcSigningKey {
				kind: AwsLcKeyKind::Pq(key),
				algorithm,
			}),
			serialized_der,
		))
	}
}

impl KeyPairProvider for AwsLcKeyPairProvider {
	fn generate(&self, algorithm: &'static SignatureAlgorithm) -> Result<KeyPair, Error> {
		if algorithm == &PKCS_ECDSA_P256_SHA256 {
			self.generate_ecdsa(algorithm, &signature::ECDSA_P256_SHA256_ASN1_SIGNING)
		} else if algorithm == &PKCS_ECDSA_P384_SHA384 {
			self.generate_ecdsa(algorithm, &signature::ECDSA_P384_SHA384_ASN1_SIGNING)
		} else if algorithm == &PKCS_ECDSA_P521_SHA256 {
			self.generate_ecdsa(algorithm, &signature::ECDSA_P521_SHA256_ASN1_SIGNING)
		} else if algorithm == &PKCS_ECDSA_P521_SHA384 {
			self.generate_ecdsa(algorithm, &signature::ECDSA_P521_SHA384_ASN1_SIGNING)
		} else if algorithm == &PKCS_ECDSA_P521_SHA512 {
			self.generate_ecdsa(algorithm, &signature::ECDSA_P521_SHA512_ASN1_SIGNING)
		} else if algorithm == &PKCS_ED25519 {
			let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
				.map_err(|_| Error::RingUnspecified)?;
			let serialized_der = document.as_ref().to_vec();
			let signing_key = self.load_with_algorithm(&serialized_der, true, algorithm)?;
			Ok(KeyPair::from_signing_key(
				Box::new(signing_key),
				serialized_der,
			))
		} else if algorithm == &PKCS_RSA_SHA256
			|| algorithm == &PKCS_RSA_SHA384
			|| algorithm == &PKCS_RSA_SHA512
		{
			self.generate_rsa_inner(algorithm, KeySize::Rsa2048)
		} else {
			#[cfg(feature = "aws_lc_rs")]
			{
				if algorithm == &PKCS_ML_DSA_44 {
					return self.generate_pqdsa(algorithm, &ML_DSA_44_SIGNING);
				}
				if algorithm == &PKCS_ML_DSA_65 {
					return self.generate_pqdsa(algorithm, &ML_DSA_65_SIGNING);
				}
				if algorithm == &PKCS_ML_DSA_87 {
					return self.generate_pqdsa(algorithm, &ML_DSA_87_SIGNING);
				}
			}
			Err(Error::UnsupportedSignatureAlgorithm)
		}
	}

	fn generate_rsa(
		&self,
		algorithm: &'static SignatureAlgorithm,
		key_size: RsaKeySize,
	) -> Result<KeyPair, Error> {
		let key_size = match key_size {
			RsaKeySize::_2048 => KeySize::Rsa2048,
			RsaKeySize::_3072 => KeySize::Rsa3072,
			RsaKeySize::_4096 => KeySize::Rsa4096,
		};
		self.generate_rsa_inner(algorithm, key_size)
	}

	fn load_private_key(
		&self,
		key_der: PrivateKeyDer<'static>,
		algorithm: Option<&'static SignatureAlgorithm>,
	) -> Result<KeyPair, Error> {
		let is_pkcs8 = matches!(key_der, PrivateKeyDer::Pkcs8(_));
		let serialized_der = key_der.secret_der().to_vec();
		let signing_key = match algorithm {
			Some(algorithm) => self.load_with_algorithm(&serialized_der, is_pkcs8, algorithm)?,
			None => self.detect(&serialized_der, is_pkcs8)?,
		};
		Ok(KeyPair::from_signing_key(
			Box::new(signing_key),
			serialized_der,
		))
	}
}

enum AwsLcKeyKind {
	Ec(EcdsaKeyPair),
	Ed(Ed25519KeyPair),
	#[cfg(feature = "aws_lc_rs")]
	Pq(PqdsaKeyPair),
	Rsa(RsaKeyPair, &'static dyn RsaEncoding),
}

struct AwsLcSigningKey {
	kind: AwsLcKeyKind,
	algorithm: &'static SignatureAlgorithm,
}

impl PublicKeyData for AwsLcSigningKey {
	fn der_bytes(&self) -> &[u8] {
		match &self.kind {
			AwsLcKeyKind::Ec(key) => key.public_key().as_ref(),
			AwsLcKeyKind::Ed(key) => key.public_key().as_ref(),
			#[cfg(feature = "aws_lc_rs")]
			AwsLcKeyKind::Pq(key) => key.public_key().as_ref(),
			AwsLcKeyKind::Rsa(key, _) => key.public_key().as_ref(),
		}
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.algorithm
	}
}

impl SigningKey for AwsLcSigningKey {
	fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
		match &self.kind {
			AwsLcKeyKind::Ec(key) => key
				.sign(&SystemRandom::new(), message)
				.map(|signature| signature.as_ref().to_vec())
				.map_err(|_| Error::RingUnspecified),
			AwsLcKeyKind::Ed(key) => Ok(key.sign(message).as_ref().to_vec()),
			#[cfg(feature = "aws_lc_rs")]
			AwsLcKeyKind::Pq(key) => {
				let mut signature = vec![0; key.algorithm().signature_len()];
				key.sign(message, &mut signature)
					.map_err(|_| Error::RingUnspecified)?;
				Ok(signature)
			},
			AwsLcKeyKind::Rsa(key, encoding) => {
				let mut signature = vec![0; key.public_modulus_len()];
				key.sign(*encoding, &SystemRandom::new(), message, &mut signature)
					.map_err(|_| Error::RingUnspecified)?;
				Ok(signature)
			},
		}
	}
}

#[derive(Debug)]
struct AwsLcSignatureVerificationProvider;

impl SignatureVerificationProvider for AwsLcSignatureVerificationProvider {
	fn verify(
		&self,
		algorithm: &'static SignatureAlgorithm,
		public_key: &[u8],
		message: &[u8],
		signature_bytes: &[u8],
	) -> Result<(), Error> {
		#[cfg(feature = "aws_lc_rs")]
		{
			let pqdsa_algorithm = if algorithm == &PKCS_ML_DSA_44 {
				Some(&ML_DSA_44)
			} else if algorithm == &PKCS_ML_DSA_65 {
				Some(&ML_DSA_65)
			} else if algorithm == &PKCS_ML_DSA_87 {
				Some(&ML_DSA_87)
			} else {
				None
			};
			if let Some(pqdsa_algorithm) = pqdsa_algorithm {
				return pqdsa_algorithm
					.verify_sig(public_key, message, signature_bytes)
					.map_err(|_| Error::SignatureVerificationFailed);
			}
		}

		let verification_algorithm: &'static dyn VerificationAlgorithm =
			if algorithm == &PKCS_ECDSA_P256_SHA256 {
				&signature::ECDSA_P256_SHA256_ASN1
			} else if algorithm == &PKCS_ECDSA_P384_SHA384 {
				&signature::ECDSA_P384_SHA384_ASN1
			} else if algorithm == &PKCS_ECDSA_P521_SHA256 {
				&signature::ECDSA_P521_SHA256_ASN1
			} else if algorithm == &PKCS_ECDSA_P521_SHA384 {
				&signature::ECDSA_P521_SHA384_ASN1
			} else if algorithm == &PKCS_ECDSA_P521_SHA512 {
				&signature::ECDSA_P521_SHA512_ASN1
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

#[cfg(test)]
mod tests {
	#[cfg(feature = "aws_lc_rs")]
	use pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

	use super::*;

	#[test]
	fn sha256_known_answer() {
		assert_eq!(
			default_provider()
				.digest(HashAlgorithm::Sha256, b"abc")
				.unwrap(),
			[
				0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
				0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
				0xf2, 0x00, 0x15, 0xad,
			]
		);
	}

	#[cfg(feature = "aws_lc_rs")]
	#[test]
	fn ml_dsa_round_trip() {
		let provider = default_provider();
		for algorithm in [&PKCS_ML_DSA_44, &PKCS_ML_DSA_65, &PKCS_ML_DSA_87] {
			let generated = KeyPair::generate_for_with_provider(algorithm, &provider).unwrap();
			let private_key = PrivatePkcs8KeyDer::from(generated.serialize_der());

			let loaded = KeyPair::from_pkcs8_der_and_sign_algo_with_provider(
				&private_key,
				algorithm,
				&provider,
			)
			.unwrap();
			assert_eq!(loaded.algorithm(), algorithm);

			let detected =
				KeyPair::from_der_with_provider(&PrivateKeyDer::Pkcs8(private_key), &provider)
					.unwrap();
			assert_eq!(detected.algorithm(), algorithm);

			let message = b"stable ML-DSA provider";
			let signature = loaded.sign(message).unwrap();
			provider
				.signature_verification_provider
				.verify(algorithm, loaded.der_bytes(), message, &signature)
				.unwrap();

			#[cfg(feature = "x509-parser")]
			{
				let request = crate::CertificateParams::default()
					.serialize_request(&loaded)
					.unwrap();
				let parsed = crate::CertificateSigningRequestParams::from_der_with_provider(
					request.der(),
					&provider,
				)
				.unwrap();
				assert_eq!(parsed.public_key.algorithm(), algorithm);
			}
		}
	}
}
