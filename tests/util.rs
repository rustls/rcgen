use time::{Duration, OffsetDateTime};
use rcgen::{BasicConstraints, Certificate, CertificateParams, CertificateRevocationList};
use rcgen::{CertificateRevocationListParams, DnType, IsCa, KeyIdMethod};
use rcgen::{KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, RevocationReason, RevokedCertParams, SerialNumber};

// Generated by adding `println!("{}", cert.serialize_private_key_pem());`
// to the test_webpki_25519 test and panicing explicitly.
// This is a "v2" key containing the public key as well as the
// private one.
#[allow(unused)]
pub const ED25519_TEST_KEY_PAIR_PEM_V2 :&str = r#"
-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIC2pHJYjFHhK8V7mj6BnHWUVMS4CRolUlDdRXKCtguDu
oSMDIQDrvH/x8Nx9untsuc6ET+ce3w7PSuLY8BLWcHdXDGvkQA==
-----END PRIVATE KEY-----
"#;
// Generated with `openssl genpkey -algorithm ED25519`
// A "v1" key as it doesn't contain the public key (which can be
// derived from the private one)
#[allow(unused)]
pub const ED25519_TEST_KEY_PAIR_PEM_V1 :&str = r#"
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSat0MacDt2fokpnzuBaXvAQR6RJGS9rgIYOU2mZKld
-----END PRIVATE KEY-----
"#;

/*
Generated by: openssl genpkey -algorithm RSA \
 -pkeyopt rsa_keygen_bits:2048 \
 -pkeyopt rsa_keygen_pubexp:65537 | \
 openssl pkcs8 -topk8 -nocrypt -outform pem
*/
#[cfg(feature = "pem")]
pub const RSA_TEST_KEY_PAIR_PEM :&str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDYjmgyV3/LSizJ
XrYrATZrrPr2Edo8yiOgBLFmi4sgeGdQ5n6nhjTGfBEIP2Ia6z+hbiGOMncabEBc
zkdME+JFYVCSkS7r4ivMOzp2egxLgcPKcerBoXI8DUbHhIR9z89lHiPHDJv3+d0A
c1b9bz9b8OAeZWiQmFvmjpbc2DfhQ2OFx2MwFZCYF196rrXOc6/SR2esZVRrkW22
RBKFTgz6GIA5A/5VWKIISSqEB1gOcMz2iq5987I28+Ez4rcLZ2lB7cZ7TbNxkAwt
0fPL+EuyP7XOzbIj4/kSAlU5xfwNERa3BEuOFro4i5EmSDj+lR5xdRpFnx0j5zOo
zUL2lHG9AgMBAAECggEARpV8DtSIOcmOeYAeXjwB8eyqy+Obv26fV/vPmr3m9glo
m2zVYWMT9pHft1F5d46v6b0MwN1gBsO74sP1Zy2f9b83VN5vbcEFR4cSkiVLtpyw
JV8mBkDKDBrDtCpUSPGgBrRhMvLAL35Ic2oks2w8OYp0clPZVi/i3G4jbA4pgIkt
yB6k79Uhzz2nfZ0VpPORGNsBOl5UK1LkmIhTJ6S0LsLj7XSet9YHR0k0F0/NOSzz
+jMUzfjOPm8M+b3wk9yAQP7qT9Iy3MHbGAad4gNXGu1LqeDRkfmM5pnoG0ASP3+B
IvX2l0ZLeCtg+GRLlGvUVI1HSQHCsuiC6/g2bq7JAQKBgQD3/Eb58VjpdwJYPrg/
srfnC9sKSf5C0Q8YSmkfvOmeD6Vqe0EXRuMyhwTkkVdz04yPiB2j0fXdeB9h16Ic
9HWb/UNGWNpV7Ul1MSHbeu32Xor+5IkqCGgSoMznlt9QPR4PxfIOgO8cVL1HgNAZ
JnBDzhTG0FfY75hqpCDmFGAZwQKBgQDfjhk5aM0yGLYgZfw/K9BrwjctQBWdrps2
4TtkG7Kuj0hsimCdrqJQ5JN8aUM41zDUr3Px1uN5gUAZ3dE9DoGsgj15ZwgVkAMM
E54bfzOqkbh+mRpptIxL4HmHB45vgvz0YljeRoOEQvPF/OSGLti7VIkD4898PFKl
cU+P9m5+/QKBgDi8XTi+AQuZEM5Duz/Hkc+opLqb5zI+RmfWTmrWe9SP29aa0G+U
5lIfFf19SzbSxavpBm7+kHPVEcj+3rYlL+s6bHPhzEIwgcfwL8DZRSxCwSZD/yXA
up7Yb0jk+b6P3RravOCYmxwuPwfm7rVyV+kLczFxZUfauVJcrrI1Iy+BAoGBAJjG
MEDGeSxaLOS5LYgyNg3ePPzkhaEruRDpHUBNmW+npZPfgSVhObXUb2IfQXwvu0Qt
3yuPcgcQKDFFIH/8UOwGWWKE4cZyk1KGeY9K/5D6Yr3JfX5tj08vSX3Y0SMtvhZ4
u0izoZ8abiOIrtdwXlau76/D2ICLbON5Kykz/NE1AoGAId2+pO9p8jBt9l+5jZo7
Rw/mb5icMaG2hqAzs37gUPbpSwQFOmGhQmNM+WvYEvUUuiTxI3AOeEK8Mj+BVB4+
uE3X/fWK/JR9iOzH9OM31Nua8/EJzr7BmUpXeRr4dAtVimeQ+5HY6IgRsFGPKKwv
YPTHy8SWRA2sMII3ArhHJ8A=
-----END PRIVATE KEY-----
"#;

pub fn default_params() -> CertificateParams {
	let mut params = CertificateParams::new(vec![
		"crabs.crabs".to_string(), "localhost".to_string(),
	]);
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Master CA");
	params
}

#[allow(unused)] // Used by openssl + x509-parser features.
pub fn test_crl() -> (CertificateRevocationList, Certificate) {
	let mut issuer = default_params();
	issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	issuer.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::CrlSign];
	let issuer = Certificate::from_params(issuer).unwrap();

	let now = OffsetDateTime::now_utc();
	let next_week = now + Duration::weeks(1);
	let revoked_cert = RevokedCertParams{
		serial_number: SerialNumber::from_slice(&[0xC0, 0xFF, 0xEE]),
		revocation_time: now,
		reason_code: Some(RevocationReason::KeyCompromise),
		invalidity_date: None,
	};

	let crl = CertificateRevocationListParams{
		this_update: now,
		next_update: next_week,
		crl_number: SerialNumber::from(1234),
		revoked_certs: vec![revoked_cert],
		alg: &PKCS_ECDSA_P256_SHA256,
		key_identifier_method: KeyIdMethod::Sha256,
	};
	let crl = CertificateRevocationList::from_params(crl).unwrap();

	(crl, issuer)
}
