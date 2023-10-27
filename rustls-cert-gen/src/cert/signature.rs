pub struct Signature<'a> {
	pub alg: &'a rcgen::SignatureAlgorithm,
	pub key_pair: rcgen::KeyPair,
}

impl Signature<'_> {
	pub fn new(s: &str) -> Result<Self, rcgen::Error> {
		match s.to_lowercase().as_str() {
			"ecdsa_p256" => Self::ecdsa_p256(),
			"ecdsa_p384" => Self::ecdsa_p384(),
			"ed25519" => Self::ed25519(),
			&_ => Err(rcgen::Error::KeyGenerationUnavailable),
		}
	}
	pub fn ed25519() -> Result<Self, rcgen::Error> {
		use ring::signature::Ed25519KeyPair;

		let rng = ring::rand::SystemRandom::new();
		let alg = &rcgen::PKCS_ED25519;
		#[rustfmt::skip]
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;

		let key_pair = rcgen::KeyPair::from_der_and_sign_algo(pkcs8_bytes.as_ref(), alg)?;

		Ok(Self { alg, key_pair })
	}

	pub fn ecdsa_p256() -> Result<Self, rcgen::Error> {
		use ring::signature::EcdsaKeyPair;
		use ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;

		let rng = ring::rand::SystemRandom::new();
		let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
		#[rustfmt::skip]
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;

		let key_pair = rcgen::KeyPair::from_der_and_sign_algo(pkcs8_bytes.as_ref(), alg)?;

		Ok(Self { alg, key_pair })
	}
	pub fn ecdsa_p384() -> Result<Self, rcgen::Error> {
		use ring::signature::EcdsaKeyPair;
		use ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING;

		let rng = ring::rand::SystemRandom::new();
		let alg = &rcgen::PKCS_ECDSA_P384_SHA384;
		#[rustfmt::skip]
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)?;

		let key_pair = rcgen::KeyPair::from_der_and_sign_algo(pkcs8_bytes.as_ref(), alg)?;

		Ok(Self { alg, key_pair })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn signature_ed25519() -> crate::Result<()> {
		let sig = Signature::new("ed25519")?;
		assert_eq!(format!("{:?}", sig.alg), "PKCS_ED25519");
		assert_eq!(format!("{:?}", sig.key_pair.algorithm()), "PKCS_ED25519");
		Ok(())
	}
	#[test]
	fn signature_ecdsa_p256_sha256() -> crate::Result<()> {
		let sig = Signature::new("ECDSA_P256")?;
		assert_eq!(format!("{:?}", sig.alg), "PKCS_ECDSA_P256_SHA256");
		assert_eq!(
			format!("{:?}", sig.key_pair.algorithm()),
			"PKCS_ECDSA_P256_SHA256"
		);
		Ok(())
	}
	#[test]
	fn signature_ecdsa_p384_sha384() -> crate::Result<()> {
		let sig = Signature::new("ECDSA_P384")?;
		assert_eq!(format!("{:?}", sig.alg), "PKCS_ECDSA_P384_SHA384");
		assert_eq!(
			format!("{:?}", sig.key_pair.algorithm()),
			"PKCS_ECDSA_P384_SHA384"
		);
		Ok(())
	}
}
