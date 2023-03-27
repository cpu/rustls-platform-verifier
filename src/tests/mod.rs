#[cfg(feature = "ffi-testing")]
pub mod ffi;

mod verification_real_world;

mod verification_mock;

use rustls::{CertificateError, Error as TlsError, Error::InvalidCertificate};

struct TestCase<'a> {
    /// The name of the server we're connecting to.
    pub reference_id: &'a str,

    /// The certificates presented by the TLS server, in the same order.
    pub chain: &'a [&'a [u8]],

    /// The stapled OCSP response given to us by Rustls, if any.
    pub stapled_ocsp: Option<&'a [u8]>,

    pub expected_result: Result<(), TlsError>,
}

pub fn assert_cert_error_eq(result: &Result<(), TlsError>, expected: &Result<(), TlsError>) {
    // If the expected error is an "Other" CertificateError we can't directly assert equality.
    // Instead, assert that the actual error matches an "Other" CertificateError pattern.
    if let Err(InvalidCertificate(CertificateError::Other(_))) = &expected {
        assert!(matches!(
            result,
            Err(InvalidCertificate(CertificateError::Other(_)))
        ))
    } else {
        assert_eq!(result, expected);
    }
}
