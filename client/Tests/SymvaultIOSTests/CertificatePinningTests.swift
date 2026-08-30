import Foundation
import Security
import Testing

@testable import SymvaultIOS

/// A short-lived, throwaway self-signed test certificate (P-256, CN=test),
/// generated once via `openssl req -x509 -newkey ec ...` purely as DER bytes
/// to feed into SecCertificateCreateWithData — it is never used to actually
/// terminate TLS, so its validity period does not matter.
private let testCertificateDER = Data(base64Encoded: """
MIIBcjCCARmgAwIBAgIUbIPB+TCDg6Qvp9JopVtO7ClBs9cwCgYIKoZIzj0EAwIw\
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjA4MzAxMDQwNTJaFw0yNjA4MzExMDQwNTJa\
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAShQ9VM\
BB6FuEbqHEiiCbhbB/uYaW64ZpRtM6Fp4csRrJ+yigYMjhlMgD5ssNIQaCMzfdPj\
ZIwg1lWRQYcMfdQXo1MwUTAdBgNVHQ4EFgQUve5LUCsd4OS7sLpaJEPSLr5i6jww\
HwYDVR0jBBgwFoAUve5LUCsd4OS7sLpaJEPSLr5i6jwwDwYDVR0TAQH/BAUwAwEB\
/zAKBggqhkjOPQQDAgNHADBEAiArLCtQQyPRguc4M0TbYO2lZSCFL4adWKg0XaqC\
1dPvzAIgf5iToo5iv9q+QHdP4zmUAEP/zVwFvXQEnUFCgr64TY0=
""")!

/// Ground truth computed independently via `shasum -a 256` on the raw DER
/// bytes above, not via any code in this repo — this is what makes the test
/// meaningful (it would not catch a bug shared between the fixture and the
/// code under test if both used the same computation).
private let expectedFingerprint = "59498b4dea6fa14b0939d69f2d4e395f08a7edc7171bcc80481c4f79916aa5e9"

private func makeTestCertificate() throws -> SecCertificate {
    guard let cert = SecCertificateCreateWithData(nil, testCertificateDER as CFData) else {
        throw TestSetupError.certificateCreationFailed
    }
    return cert
}

private enum TestSetupError: Error {
    case certificateCreationFailed
}

@Test func fingerprintMatchesIndependentlyComputedValue() throws {
    let cert = try makeTestCertificate()
    #expect(CertificatePinning.fingerprint(of: cert) == expectedFingerprint)
}

@Test func matchesAcceptsCorrectFingerprint() throws {
    let cert = try makeTestCertificate()
    #expect(CertificatePinning.matches(cert, expected: expectedFingerprint))
}

@Test func matchesIsCaseInsensitive() throws {
    let cert = try makeTestCertificate()
    #expect(CertificatePinning.matches(cert, expected: expectedFingerprint.uppercased()))
}

@Test func matchesRejectsWrongFingerprint() throws {
    let cert = try makeTestCertificate()
    #expect(!CertificatePinning.matches(cert, expected: "0000000000000000000000000000000000000000000000000000000000000000"))
}
