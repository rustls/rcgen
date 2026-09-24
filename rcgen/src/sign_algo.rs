use std::fmt;
use std::hash::{Hash, Hasher};

#[cfg(feature = "aws_lc_rs")]
use aws_lc_rs::signature::{
	PqdsaSigningAlgorithm, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING,
};
use yasna::models::ObjectIdentifier;
use yasna::DERWriter;

#[cfg(feature = "crypto")]
use crate::ring_like::signature::{self, EcdsaSigningAlgorithm, EdDSAParameters, RsaEncoding};
#[cfg(feature = "x509-parser")]
use crate::Error;

#[cfg(feature = "crypto")]
#[derive(Clone, Copy, Debug)]
pub(crate) enum SignAlgo {
	EcDsa(&'static EcdsaSigningAlgorithm),
	EdDsa(&'static EdDSAParameters),
	#[cfg(feature = "aws_lc_rs")]
	PqDsa(&'static PqdsaSigningAlgorithm),
	Rsa(&'static dyn RsaEncoding),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SignatureAlgorithmParams {
	/// Omit the parameters
	None,
	/// Write null parameters
	Null,
}

/// The parameters of a public key's `AlgorithmIdentifier`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum PublicKeyParameters {
	/// Omit the parameters
	Absent,
	/// Write null parameters
	Null,
	/// Write a named curve OID
	NamedCurve(&'static [u64]),
}

/// The algorithm of a public key, as identified in a `SubjectPublicKeyInfo`
#[derive(Clone)]
pub struct PublicKeyAlgorithm {
	name: &'static str,
	oid_components: &'static [u64],
	params: PublicKeyParameters,
}

impl PublicKeyAlgorithm {
	#[cfg(any(feature = "x509-parser", test))]
	pub(crate) fn iter() -> std::slice::Iter<'static, &'static PublicKeyAlgorithm> {
		use key_alg::*;
		static ALGORITHMS: &[&PublicKeyAlgorithm] = &[
			&RSA,
			&ECDSA_P256,
			&ECDSA_P384,
			#[cfg(feature = "aws_lc_rs")]
			&ECDSA_P521,
			&ED25519,
			#[cfg(feature = "aws_lc_rs")]
			&ML_DSA_44,
			#[cfg(feature = "aws_lc_rs")]
			&ML_DSA_65,
			#[cfg(feature = "aws_lc_rs")]
			&ML_DSA_87,
		];
		ALGORITHMS.iter()
	}

	/// Retrieve the `PublicKeyAlgorithm` matching a parsed `AlgorithmIdentifier`
	#[cfg(feature = "x509-parser")]
	pub(crate) fn from_alg_id(
		alg_id: &x509_parser::x509::AlgorithmIdentifier<'_>,
	) -> Result<&'static Self, Error> {
		use x509_parser::prelude::FromDer;

		Self::iter()
			.find(|alg| {
				let der = yasna::construct_der(|writer| alg.write_alg_id(writer));
				let Ok((rest, parsed)) = x509_parser::x509::AlgorithmIdentifier::from_der(&der)
				else {
					return false;
				};
				rest.is_empty() && &parsed == alg_id
			})
			.copied()
			.ok_or(Error::UnsupportedPublicKeyAlgorithm)
	}

	/// Writes the algorithm identifier as it appears inside a `SubjectPublicKeyInfo`
	pub(crate) fn write_alg_id(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			writer
				.next()
				.write_oid(&ObjectIdentifier::from_slice(self.oid_components));
			match self.params {
				PublicKeyParameters::Absent => {},
				PublicKeyParameters::Null => writer.next().write_null(),
				PublicKeyParameters::NamedCurve(curve) => writer
					.next()
					.write_oid(&ObjectIdentifier::from_slice(curve)),
			}
		});
	}
}

impl fmt::Debug for PublicKeyAlgorithm {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.name)
	}
}

impl PartialEq for PublicKeyAlgorithm {
	fn eq(&self, other: &Self) -> bool {
		(self.oid_components, self.params) == (other.oid_components, other.params)
	}
}

impl Eq for PublicKeyAlgorithm {}

/// The `Hash` trait is not derived, but implemented according to impl of the `PartialEq` trait
impl Hash for PublicKeyAlgorithm {
	fn hash<H: Hasher>(&self, state: &mut H) {
		(self.oid_components, self.params).hash(state);
	}
}

/// The list of supported public key algorithms
pub mod key_alg {
	use super::{PublicKeyAlgorithm, PublicKeyParameters};
	use crate::oid::*;

	/// RSA public keys, as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static RSA: PublicKeyAlgorithm = PublicKeyAlgorithm {
		name: "RSA",
		oid_components: RSA_ENCRYPTION,
		params: PublicKeyParameters::Null,
	};

	/// ECDSA public keys on the P-256 curve, as per [RFC 5480](https://tools.ietf.org/html/rfc5480)
	pub static ECDSA_P256: PublicKeyAlgorithm = PublicKeyAlgorithm {
		name: "ECDSA_P256",
		oid_components: EC_PUBLIC_KEY,
		params: PublicKeyParameters::NamedCurve(EC_SECP_256_R1),
	};

	/// ECDSA public keys on the P-384 curve, as per [RFC 5480](https://tools.ietf.org/html/rfc5480)
	pub static ECDSA_P384: PublicKeyAlgorithm = PublicKeyAlgorithm {
		name: "ECDSA_P384",
		oid_components: EC_PUBLIC_KEY,
		params: PublicKeyParameters::NamedCurve(EC_SECP_384_R1),
	};

	/// ECDSA public keys on the P-521 curve, as per [RFC 5480](https://tools.ietf.org/html/rfc5480)
	///
	/// Only supported with the `aws_lc_rs` backend.
	#[cfg(feature = "aws_lc_rs")]
	pub static ECDSA_P521: PublicKeyAlgorithm = PublicKeyAlgorithm {
		name: "ECDSA_P521",
		oid_components: EC_PUBLIC_KEY,
		params: PublicKeyParameters::NamedCurve(EC_SECP_521_R1),
	};

	/// Ed25519 public keys, as per [RFC 8410](https://tools.ietf.org/html/rfc8410)
	pub static ED25519: PublicKeyAlgorithm = PublicKeyAlgorithm {
		name: "ED25519",
		// id-Ed25519 in RFC 8410
		oid_components: &[1, 3, 101, 112],
		params: PublicKeyParameters::Absent,
	};

	/// ML-DSA-44 public keys, as per [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881)
	#[cfg(feature = "aws_lc_rs")]
	pub static ML_DSA_44: PublicKeyAlgorithm = PublicKeyAlgorithm {
		name: "ML_DSA_44",
		oid_components: crate::oid::ML_DSA_44,
		params: PublicKeyParameters::Absent,
	};

	/// ML-DSA-65 public keys, as per [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881)
	#[cfg(feature = "aws_lc_rs")]
	pub static ML_DSA_65: PublicKeyAlgorithm = PublicKeyAlgorithm {
		name: "ML_DSA_65",
		oid_components: crate::oid::ML_DSA_65,
		params: PublicKeyParameters::Absent,
	};

	/// ML-DSA-87 public keys, as per [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881)
	#[cfg(feature = "aws_lc_rs")]
	pub static ML_DSA_87: PublicKeyAlgorithm = PublicKeyAlgorithm {
		name: "ML_DSA_87",
		oid_components: crate::oid::ML_DSA_87,
		params: PublicKeyParameters::Absent,
	};
}

/// Signature algorithm type
#[derive(Clone)]
pub struct SignatureAlgorithm {
	name: &'static str,
	key_alg: &'static PublicKeyAlgorithm,
	#[cfg(feature = "crypto")]
	pub(crate) sign_alg: SignAlgo,
	oid_components: &'static [u64],
	params: SignatureAlgorithmParams,
}

impl fmt::Debug for SignatureAlgorithm {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.name)
	}
}

impl PartialEq for SignatureAlgorithm {
	fn eq(&self, other: &Self) -> bool {
		(self.key_alg, self.oid_components) == (other.key_alg, other.oid_components)
	}
}

impl Eq for SignatureAlgorithm {}

/// The `Hash` trait is not derived, but implemented according to impl of the `PartialEq` trait
impl Hash for SignatureAlgorithm {
	fn hash<H: Hasher>(&self, state: &mut H) {
		// see SignatureAlgorithm::eq(), just these fields are compared
		(self.key_alg, self.oid_components).hash(state);
	}
}
impl SignatureAlgorithm {
	#[cfg(test)]
	pub(crate) fn iter() -> std::slice::Iter<'static, &'static SignatureAlgorithm> {
		use algo::*;
		static ALGORITHMS: &[&SignatureAlgorithm] = &[
			&RSA_PKCS1_SHA256,
			&RSA_PKCS1_SHA384,
			&RSA_PKCS1_SHA512,
			&ECDSA_P256_SHA256,
			&ECDSA_P384_SHA384,
			#[cfg(feature = "aws_lc_rs")]
			&ECDSA_P521_SHA256,
			#[cfg(feature = "aws_lc_rs")]
			&ECDSA_P521_SHA384,
			#[cfg(feature = "aws_lc_rs")]
			&ECDSA_P521_SHA512,
			&ED25519,
			#[cfg(feature = "aws_lc_rs")]
			&ML_DSA_44,
			#[cfg(feature = "aws_lc_rs")]
			&ML_DSA_65,
			#[cfg(feature = "aws_lc_rs")]
			&ML_DSA_87,
		];
		ALGORITHMS.iter()
	}

	/// The algorithm of a public key that produces signatures with this algorithm
	pub fn public_key_algorithm(&self) -> &'static PublicKeyAlgorithm {
		self.key_alg
	}
}

/// The list of supported signature algorithms
pub(crate) mod algo {
	use super::*;

	/// RSA signing with PKCS#1 1.5 padding and SHA-256 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static RSA_PKCS1_SHA256: SignatureAlgorithm = SignatureAlgorithm {
		name: "RSA_PKCS1_SHA256",
		key_alg: &key_alg::RSA,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::Rsa(&signature::RSA_PKCS1_SHA256),
		// sha256WithRSAEncryption in RFC 4055
		oid_components: &[1, 2, 840, 113549, 1, 1, 11],
		params: SignatureAlgorithmParams::Null,
	};

	/// RSA signing with PKCS#1 1.5 padding and SHA-384 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static RSA_PKCS1_SHA384: SignatureAlgorithm = SignatureAlgorithm {
		name: "RSA_PKCS1_SHA384",
		key_alg: &key_alg::RSA,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::Rsa(&signature::RSA_PKCS1_SHA384),
		// sha384WithRSAEncryption in RFC 4055
		oid_components: &[1, 2, 840, 113549, 1, 1, 12],
		params: SignatureAlgorithmParams::Null,
	};

	/// RSA signing with PKCS#1 1.5 padding and SHA-512 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static RSA_PKCS1_SHA512: SignatureAlgorithm = SignatureAlgorithm {
		name: "RSA_PKCS1_SHA512",
		key_alg: &key_alg::RSA,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::Rsa(&signature::RSA_PKCS1_SHA512),
		// sha512WithRSAEncryption in RFC 4055
		oid_components: &[1, 2, 840, 113549, 1, 1, 13],
		params: SignatureAlgorithmParams::Null,
	};

	/// ECDSA signing using the P-256 curves and SHA-256 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	pub static ECDSA_P256_SHA256: SignatureAlgorithm = SignatureAlgorithm {
		name: "ECDSA_P256_SHA256",
		key_alg: &key_alg::ECDSA_P256,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EcDsa(&signature::ECDSA_P256_SHA256_ASN1_SIGNING),
		// ecdsa-with-SHA256 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 2],
		params: SignatureAlgorithmParams::None,
	};

	/// ECDSA signing using the P-384 curves and SHA-384 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	pub static ECDSA_P384_SHA384: SignatureAlgorithm = SignatureAlgorithm {
		name: "ECDSA_P384_SHA384",
		key_alg: &key_alg::ECDSA_P384,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EcDsa(&signature::ECDSA_P384_SHA384_ASN1_SIGNING),
		// ecdsa-with-SHA384 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 3],
		params: SignatureAlgorithmParams::None,
	};

	/// ECDSA signing using the P-521 curves and SHA-256 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	///
	/// Note that this algorithm is not widely supported, and is not supported in TLS 1.3.
	///
	/// Only supported with the `aws_lc_rs` backend.
	#[cfg(feature = "aws_lc_rs")]
	pub static ECDSA_P521_SHA256: SignatureAlgorithm = SignatureAlgorithm {
		name: "ECDSA_P521_SHA256",
		key_alg: &key_alg::ECDSA_P521,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EcDsa(&signature::ECDSA_P521_SHA256_ASN1_SIGNING),
		// ecdsa-with-SHA256 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 2],
		params: SignatureAlgorithmParams::None,
	};

	/// ECDSA signing using the P-521 curves and SHA-384 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	///
	/// Note that this algorithm is not widely supported, and is not supported in TLS 1.3.
	///
	/// Only supported with the `aws_lc_rs` backend.
	#[cfg(feature = "aws_lc_rs")]
	pub static ECDSA_P521_SHA384: SignatureAlgorithm = SignatureAlgorithm {
		name: "ECDSA_P521_SHA384",
		key_alg: &key_alg::ECDSA_P521,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EcDsa(&signature::ECDSA_P521_SHA384_ASN1_SIGNING),
		// ecdsa-with-SHA384 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 3],
		params: SignatureAlgorithmParams::None,
	};

	/// ECDSA signing using the P-521 curves and SHA-512 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	///
	/// Only supported with the `aws_lc_rs` backend.
	#[cfg(feature = "aws_lc_rs")]
	pub static ECDSA_P521_SHA512: SignatureAlgorithm = SignatureAlgorithm {
		name: "ECDSA_P521_SHA512",
		key_alg: &key_alg::ECDSA_P521,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EcDsa(&signature::ECDSA_P521_SHA512_ASN1_SIGNING),
		// ecdsa-with-SHA512 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 4],
		params: SignatureAlgorithmParams::None,
	};

	/// ED25519 curve signing as per [RFC 8410](https://tools.ietf.org/html/rfc8410)
	pub static ED25519: SignatureAlgorithm = SignatureAlgorithm {
		name: "ED25519",
		key_alg: &key_alg::ED25519,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EdDsa(&signature::ED25519),
		// id-Ed25519 in RFC 8410
		oid_components: &[1, 3, 101, 112],
		params: SignatureAlgorithmParams::None,
	};

	/// ML-DSA-44 signing as per <https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-12.html#name-identifiers>.
	#[cfg(feature = "aws_lc_rs")]
	pub static ML_DSA_44: SignatureAlgorithm = SignatureAlgorithm {
		name: "ML_DSA_44",
		key_alg: &key_alg::ML_DSA_44,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::PqDsa(&ML_DSA_44_SIGNING),
		oid_components: crate::oid::ML_DSA_44,
		params: SignatureAlgorithmParams::None,
	};

	/// ML-DSA-65 signing as per <https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-12.html#name-identifiers>.
	#[cfg(feature = "aws_lc_rs")]
	pub static ML_DSA_65: SignatureAlgorithm = SignatureAlgorithm {
		name: "ML_DSA_65",
		key_alg: &key_alg::ML_DSA_65,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::PqDsa(&ML_DSA_65_SIGNING),
		oid_components: crate::oid::ML_DSA_65,
		params: SignatureAlgorithmParams::None,
	};

	/// ML-DSA-87 signing as per <https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-12.html#name-identifiers>.
	#[cfg(feature = "aws_lc_rs")]
	pub static ML_DSA_87: SignatureAlgorithm = SignatureAlgorithm {
		name: "ML_DSA_87",
		key_alg: &key_alg::ML_DSA_87,
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::PqDsa(&ML_DSA_87_SIGNING),
		oid_components: crate::oid::ML_DSA_87,
		params: SignatureAlgorithmParams::None,
	};
}
// Signature algorithm IDs as per https://tools.ietf.org/html/rfc4055
impl SignatureAlgorithm {
	fn alg_ident_oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(self.oid_components)
	}
	fn write_params(&self, writer: &mut yasna::DERWriterSeq) {
		match self.params {
			SignatureAlgorithmParams::None => (),
			SignatureAlgorithmParams::Null => {
				writer.next().write_null();
			},
		}
	}
	/// Writes the algorithm identifier as it appears inside a signature
	pub(crate) fn write_alg_ident(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			writer.next().write_oid(&self.alg_ident_oid());
			self.write_params(writer);
		});
	}
}
