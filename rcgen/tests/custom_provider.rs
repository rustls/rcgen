#![cfg(feature = "crypto")]

use std::sync::atomic::{AtomicUsize, Ordering};

use pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rcgen::crypto::{
	CryptoProvider, DigestProvider, HashAlgorithm, KeyPairProvider, SignatureVerificationProvider,
};
use rcgen::{
	BasicConstraints, CertificateParams, CertificateRevocationListParams, Error, IsCa, Issuer,
	KeyIdMethod, KeyPair, PublicKeyData, RsaKeySize, SerialNumber, SignatureAlgorithm, SigningKey,
	PKCS_ED25519, PKCS_RSA_SHA256,
};

static GENERATIONS: AtomicUsize = AtomicUsize::new(0);
static RSA_GENERATIONS: AtomicUsize = AtomicUsize::new(0);
static LOADS: AtomicUsize = AtomicUsize::new(0);
static DIGESTS: AtomicUsize = AtomicUsize::new(0);
static VERIFICATIONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct TestBackend;

static TEST_BACKEND: TestBackend = TestBackend;

fn provider() -> CryptoProvider {
	CryptoProvider {
		key_pair_provider: &TEST_BACKEND,
		digest_provider: &TEST_BACKEND,
		signature_verification_provider: &TEST_BACKEND,
	}
}

impl DigestProvider for TestBackend {
	fn digest(
		&self,
		algorithm: HashAlgorithm,
		input: &[u8],
		output: &mut [u8],
	) -> Result<(), Error> {
		assert_eq!(output.len(), algorithm.output_len());
		assert!(!input.is_empty());
		DIGESTS.fetch_add(1, Ordering::Relaxed);
		output.fill(0x42);
		Ok(())
	}
}

impl KeyPairProvider for TestBackend {
	fn generate(
		&self,
		algorithm: &'static SignatureAlgorithm,
		key_size: Option<RsaKeySize>,
	) -> Result<KeyPair, Error> {
		if let Some(key_size) = key_size {
			assert_eq!(key_size, RsaKeySize::_3072);
			RSA_GENERATIONS.fetch_add(1, Ordering::Relaxed);
			return Err(Error::KeyGenerationUnavailable);
		}
		GENERATIONS.fetch_add(1, Ordering::Relaxed);
		Ok(test_key_pair(algorithm, vec![0x30, 0x00]))
	}

	fn load_private_key(
		&self,
		key_der: PrivateKeyDer<'static>,
		algorithm: Option<&'static SignatureAlgorithm>,
	) -> Result<KeyPair, Error> {
		LOADS.fetch_add(1, Ordering::Relaxed);
		Ok(test_key_pair(
			algorithm.unwrap_or(&PKCS_ED25519),
			key_der.secret_der().to_vec(),
		))
	}
}

impl SignatureVerificationProvider for TestBackend {
	fn verify(
		&self,
		algorithm: &'static SignatureAlgorithm,
		public_key: &[u8],
		message: &[u8],
		signature: &[u8],
	) -> Result<(), Error> {
		assert_eq!(algorithm, &PKCS_ED25519);
		assert_eq!(public_key, [7; 32]);
		assert!(!message.is_empty());
		assert_eq!(signature, [9; 64]);
		VERIFICATIONS.fetch_add(1, Ordering::Relaxed);
		Ok(())
	}
}

struct TestSigningKey {
	algorithm: &'static SignatureAlgorithm,
	public_key: [u8; 32],
}

impl PublicKeyData for TestSigningKey {
	fn der_bytes(&self) -> &[u8] {
		&self.public_key
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.algorithm
	}
}

impl SigningKey for TestSigningKey {
	fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, Error> {
		Ok(vec![9; 64])
	}
}

fn test_key_pair(algorithm: &'static SignatureAlgorithm, serialized_der: Vec<u8>) -> KeyPair {
	KeyPair::from_signing_key(
		Box::new(TestSigningKey {
			algorithm,
			public_key: [7; 32],
		}),
		serialized_der,
	)
}

#[test]
fn explicit_provider_covers_all_rcgen_crypto() {
	assert!(CryptoProvider::get_default().is_none());
	#[cfg(not(any(feature = "ring", feature = "aws_lc_rs")))]
	assert_eq!(
		KeyPair::generate().unwrap_err(),
		Error::CryptoProviderNotInstalled
	);
	let custom_provider = provider();
	let key = KeyPair::generate_for_with_provider(&PKCS_ED25519, &custom_provider).unwrap();
	assert_eq!(GENERATIONS.load(Ordering::Relaxed), 1);
	assert_eq!(
		KeyPair::generate_rsa_for_with_provider(
			&PKCS_RSA_SHA256,
			RsaKeySize::_3072,
			&custom_provider,
		)
		.unwrap_err(),
		Error::KeyGenerationUnavailable
	);
	assert_eq!(RSA_GENERATIONS.load(Ordering::Relaxed), 1);

	let mut params = CertificateParams::default();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let certificate = params
		.self_signed_with_provider(&key, &custom_provider)
		.unwrap();
	assert!(!certificate.der().is_empty());
	assert!(DIGESTS.load(Ordering::Relaxed) >= 2); // default serial and subject key ID

	let issuer = Issuer::new(params, key);
	let crl = CertificateRevocationListParams {
		this_update: rcgen::date_time_ymd(2025, 1, 1),
		next_update: rcgen::date_time_ymd(2026, 1, 1),
		crl_number: SerialNumber::from(1u64),
		issuing_distribution_point: None,
		revoked_certs: Vec::new(),
		key_identifier_method: KeyIdMethod::Sha384,
	}
	.signed_by_with_provider(&issuer, &custom_provider)
	.unwrap();
	assert!(!crl.der().is_empty());

	let fake_der = PrivatePkcs8KeyDer::from(vec![0x30, 0x00]);
	let loaded = KeyPair::from_pkcs8_der_and_sign_algo_with_provider(
		&fake_der,
		&PKCS_ED25519,
		&custom_provider,
	)
	.unwrap();
	assert_eq!(loaded.algorithm(), &PKCS_ED25519);
	assert_eq!(LOADS.load(Ordering::Relaxed), 1);

	#[cfg(feature = "x509-parser")]
	{
		let request = CertificateParams::default()
			.serialize_request(&loaded)
			.unwrap();
		let parsed = rcgen::CertificateSigningRequestParams::from_der_with_provider(
			request.der(),
			&custom_provider,
		)
		.unwrap();
		assert_eq!(parsed.public_key.algorithm(), &PKCS_ED25519);
		assert_eq!(VERIFICATIONS.load(Ordering::Relaxed), 1);
	}

	assert!(CryptoProvider::get_default().is_none());
	provider().install_default().unwrap();
	let generated = KeyPair::generate_for(&PKCS_ED25519).unwrap();
	assert_eq!(generated.algorithm(), &PKCS_ED25519);
	assert_eq!(GENERATIONS.load(Ordering::Relaxed), 2);
	assert!(provider().install_default().is_err());
}
