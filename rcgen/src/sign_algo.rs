use std::fmt;
use std::hash::{Hash, Hasher};

use yasna::models::ObjectIdentifier;
use yasna::DERWriter;

use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SignatureAlgorithmParams {
	/// Omit the parameters
	None,
	/// Write null parameters
	Null,
}

/// Signature algorithm type
#[derive(Clone)]
pub struct SignatureAlgorithm {
	oids_sign_alg: &'static [&'static [u64]],
	oid_components: &'static [u64],
	params: SignatureAlgorithmParams,
}

impl fmt::Debug for SignatureAlgorithm {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		use algo::*;
		if self == &PKCS_RSA_SHA256 {
			write!(f, "PKCS_RSA_SHA256")
		} else if self == &PKCS_RSA_SHA384 {
			write!(f, "PKCS_RSA_SHA384")
		} else if self == &PKCS_RSA_SHA512 {
			write!(f, "PKCS_RSA_SHA512")
		} else if self == &PKCS_ECDSA_P256_SHA256 {
			write!(f, "PKCS_ECDSA_P256_SHA256")
		} else if self == &PKCS_ECDSA_P384_SHA384 {
			write!(f, "PKCS_ECDSA_P384_SHA384")
		} else if self == &PKCS_ED25519 {
			write!(f, "PKCS_ED25519")
		} else if self == &PKCS_ECDSA_P521_SHA256 {
			write!(f, "PKCS_ECDSA_P521_SHA256")
		} else if self == &PKCS_ECDSA_P521_SHA384 {
			write!(f, "PKCS_ECDSA_P521_SHA384")
		} else if self == &PKCS_ECDSA_P521_SHA512 {
			write!(f, "PKCS_ECDSA_P521_SHA512")
		} else {
			write!(f, "Unknown")
		}
	}
}

impl PartialEq for SignatureAlgorithm {
	fn eq(&self, other: &Self) -> bool {
		(self.oids_sign_alg, self.oid_components) == (other.oids_sign_alg, other.oid_components)
	}
}

impl Eq for SignatureAlgorithm {}

/// The `Hash` trait is not derived, but implemented according to impl of the `PartialEq` trait
impl Hash for SignatureAlgorithm {
	fn hash<H: Hasher>(&self, state: &mut H) {
		// see SignatureAlgorithm::eq(), just this field is compared
		self.oids_sign_alg.hash(state);
	}
}
impl SignatureAlgorithm {
	pub(crate) fn iter() -> std::slice::Iter<'static, &'static SignatureAlgorithm> {
		use algo::*;
		static ALGORITHMS: &[&SignatureAlgorithm] = &[
			&PKCS_RSA_SHA256,
			&PKCS_RSA_SHA384,
			&PKCS_RSA_SHA512,
			&PKCS_ECDSA_P256_SHA256,
			&PKCS_ECDSA_P384_SHA384,
			&PKCS_ECDSA_P521_SHA256,
			&PKCS_ECDSA_P521_SHA384,
			&PKCS_ECDSA_P521_SHA512,
			&PKCS_ED25519,
			#[cfg(feature = "aws_lc_rs")]
			&PKCS_ML_DSA_44,
			#[cfg(feature = "aws_lc_rs")]
			&PKCS_ML_DSA_65,
			#[cfg(feature = "aws_lc_rs")]
			&PKCS_ML_DSA_87,
		];
		ALGORITHMS.iter()
	}

	/// Retrieve the SignatureAlgorithm for the provided OID
	pub fn from_oid(oid: &[u64]) -> Result<&'static SignatureAlgorithm, Error> {
		for algo in Self::iter() {
			if algo.oid_components == oid {
				return Ok(algo);
			}
		}
		Err(Error::UnsupportedSignatureAlgorithm)
	}

	#[cfg(feature = "x509-parser")]
	pub(crate) fn matches_signature_oid(&self, oid: &[u64]) -> bool {
		self.oid_components == oid
	}
}

/// The list of supported signature algorithms
pub(crate) mod algo {
	use super::*;
	use crate::oid::*;

	/// RSA signing with PKCS#1 1.5 padding and SHA-256 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static PKCS_RSA_SHA256: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[RSA_ENCRYPTION],
		// sha256WithRSAEncryption in RFC 4055
		oid_components: &[1, 2, 840, 113549, 1, 1, 11],
		params: SignatureAlgorithmParams::Null,
	};

	/// RSA signing with PKCS#1 1.5 padding and SHA-384 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static PKCS_RSA_SHA384: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[RSA_ENCRYPTION],
		// sha384WithRSAEncryption in RFC 4055
		oid_components: &[1, 2, 840, 113549, 1, 1, 12],
		params: SignatureAlgorithmParams::Null,
	};

	/// RSA signing with PKCS#1 1.5 padding and SHA-512 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static PKCS_RSA_SHA512: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[RSA_ENCRYPTION],
		// sha512WithRSAEncryption in RFC 4055
		oid_components: &[1, 2, 840, 113549, 1, 1, 13],
		params: SignatureAlgorithmParams::Null,
	};

	/// ECDSA signing using the P-256 curves and SHA-256 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	pub static PKCS_ECDSA_P256_SHA256: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[EC_PUBLIC_KEY, EC_SECP_256_R1],
		// ecdsa-with-SHA256 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 2],
		params: SignatureAlgorithmParams::None,
	};

	/// ECDSA signing using the P-384 curves and SHA-384 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	pub static PKCS_ECDSA_P384_SHA384: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[EC_PUBLIC_KEY, EC_SECP_384_R1],
		// ecdsa-with-SHA384 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 3],
		params: SignatureAlgorithmParams::None,
	};

	/// ECDSA signing using the P-521 curves and SHA-256 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	///
	/// Note that this algorithm is not widely supported, and is not supported in TLS 1.3.
	///
	/// Only supported by the built-in `aws_lc_rs` provider, or a custom provider that implements it.
	pub static PKCS_ECDSA_P521_SHA256: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[EC_PUBLIC_KEY, EC_SECP_521_R1],
		// ecdsa-with-SHA256 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 2],
		params: SignatureAlgorithmParams::None,
	};

	/// ECDSA signing using the P-521 curves and SHA-384 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	///
	/// Note that this algorithm is not widely supported, and is not supported in TLS 1.3.
	///
	/// Only supported by the built-in `aws_lc_rs` provider, or a custom provider that implements it.
	pub static PKCS_ECDSA_P521_SHA384: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[EC_PUBLIC_KEY, EC_SECP_521_R1],
		// ecdsa-with-SHA384 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 3],
		params: SignatureAlgorithmParams::None,
	};

	/// ECDSA signing using the P-521 curves and SHA-512 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	///
	/// Only supported by the built-in `aws_lc_rs` provider, or a custom provider that implements it.
	pub static PKCS_ECDSA_P521_SHA512: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[EC_PUBLIC_KEY, EC_SECP_521_R1],
		// ecdsa-with-SHA512 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 4],
		params: SignatureAlgorithmParams::None,
	};

	/// ED25519 curve signing as per [RFC 8410](https://tools.ietf.org/html/rfc8410)
	pub static PKCS_ED25519: SignatureAlgorithm = SignatureAlgorithm {
		// id-Ed25519 in RFC 8410
		oids_sign_alg: &[&[1, 3, 101, 112]],
		// id-Ed25519 in RFC 8410
		oid_components: &[1, 3, 101, 112],
		params: SignatureAlgorithmParams::None,
	};

	/// ML-DSA-44 signing as per <https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-12.html#name-identifiers>.
	#[cfg(feature = "aws_lc_rs")]
	pub static PKCS_ML_DSA_44: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[ML_DSA_44],
		oid_components: ML_DSA_44,
		params: SignatureAlgorithmParams::None,
	};

	/// ML-DSA-65 signing as per <https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-12.html#name-identifiers>.
	#[cfg(feature = "aws_lc_rs")]
	pub static PKCS_ML_DSA_65: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[ML_DSA_65],
		oid_components: ML_DSA_65,
		params: SignatureAlgorithmParams::None,
	};

	/// ML-DSA-87 signing as per <https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-12.html#name-identifiers>.
	#[cfg(feature = "aws_lc_rs")]
	pub static PKCS_ML_DSA_87: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[ML_DSA_87],
		oid_components: ML_DSA_87,
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
	/// Writes the algorithm identifier as it appears inside subjectPublicKeyInfo
	pub(crate) fn write_oids_sign_alg(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			for oid in self.oids_sign_alg {
				let oid = ObjectIdentifier::from_slice(oid);
				writer.next().write_oid(&oid);
			}
			self.write_params(writer);
		});
	}
}
