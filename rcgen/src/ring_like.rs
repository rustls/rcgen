#[cfg(all(feature = "crypto", feature = "ring"))]
pub(crate) use ring::*;

#[cfg(all(feature = "crypto", not(feature = "ring"), feature = "aws_lc_rs"))]
pub(crate) use aws_lc_rs::*;

#[cfg(feature = "crypto")]
use crate::error::ExternalError;
#[cfg(feature = "crypto")]
use crate::Error;

#[cfg(feature = "crypto")]
pub(crate) fn ecdsa_from_pkcs8(
	alg: &'static signature::EcdsaSigningAlgorithm,
	pkcs8: &[u8],
	_rng: &dyn rand::SecureRandom,
) -> Result<signature::EcdsaKeyPair, Error> {
	#[cfg(feature = "ring")]
	{
		signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8, _rng)._err()
	}

	#[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
	{
		Ok(signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8)._err()?)
	}
}

#[cfg(feature = "crypto")]
pub(crate) fn rsa_key_pair_public_modulus_len(kp: &signature::RsaKeyPair) -> usize {
	#[cfg(feature = "ring")]
	{
		kp.public().modulus_len()
	}

	#[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
	{
		kp.public_modulus_len()
	}
}

#[cfg(all(feature = "crypto", not(any(feature = "ring", feature = "aws_lc_rs"))))]
compile_error!("At least one of the 'ring' or 'aws_lc_rs' features must be activated when the 'crypto' feature is enabled");
