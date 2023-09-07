/// pkcs-9-at-extensionRequest in RFC 2985
pub const OID_PKCS_9_AT_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];

/// id-at-countryName in RFC 5280
pub const OID_COUNTRY_NAME: &[u64] = &[2, 5, 4, 6];
/// id-at-localityName in RFC 5280
pub const OID_LOCALITY_NAME: &[u64] = &[2, 5, 4, 7];
/// id-at-stateOrProvinceName in RFC 5280
pub const OID_STATE_OR_PROVINCE_NAME: &[u64] = &[2, 5, 4, 8];
/// id-at-organizationName in RFC 5280
pub const OID_ORG_NAME: &[u64] = &[2, 5, 4, 10];
/// id-at-organizationalUnitName in RFC 5280
pub const OID_ORG_UNIT_NAME: &[u64] = &[2, 5, 4, 11];
/// id-at-commonName in RFC 5280
pub const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];

// https://tools.ietf.org/html/rfc5480#section-2.1.1
pub const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
pub const OID_EC_SECP_256_R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
pub const OID_EC_SECP_384_R1: &[u64] = &[1, 3, 132, 0, 34];

// rsaEncryption in RFC 4055
pub const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];

// id-RSASSA-PSS in RFC 4055
pub const OID_RSASSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
pub const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];

// https://tools.ietf.org/html/rfc5280#appendix-A.2
// https://tools.ietf.org/html/rfc5280#section-4.2.1.6
pub const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
pub const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];

// https://tools.ietf.org/html/rfc5280#section-4.2.1.2
pub const OID_SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];

// https://tools.ietf.org/html/rfc5280#section-4.2.1.1
pub const OID_AUTHORITY_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 35];

// id-ce-extKeyUsage in
// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
pub const OID_EXT_KEY_USAGE: &[u64] = &[2, 5, 29, 37];

// id-ce-nameConstraints in
// https://tools.ietf.org/html/rfc5280#section-4.2.1.10
pub const OID_NAME_CONSTRAINTS: &[u64] = &[2, 5, 29, 30];

// id-ce-cRLDistributionPoints in
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13
pub const OID_CRL_DISTRIBUTION_POINTS: &[u64] = &[2, 5, 29, 31];

// id-pe-acmeIdentifier in
// https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.1
pub const OID_PE_ACME: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

// id-ce-cRLNumber in
// https://www.rfc-editor.org/rfc/rfc5280#section-5.2.3
pub const OID_CRL_NUMBER: &[u64] = &[2, 5, 29, 20];

// id-ce-cRLReasons
// https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1
pub const OID_CRL_REASONS: &[u64] = &[2, 5, 29, 21];

// id-ce-invalidityDate
// https://www.rfc-editor.org/rfc/rfc5280#section-5.3.2
pub const OID_CRL_INVALIDITY_DATE: &[u64] = &[2, 5, 29, 24];

// id-ce-issuingDistributionPoint
// https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5
pub const OID_CRL_ISSUING_DISTRIBUTION_POINT: &[u64] = &[2, 5, 29, 28];
