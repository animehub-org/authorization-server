package org.animefoda.authorizationserver.request;

public record LoginRequest(
    String email,
    String username,
    String password,
    UserFingerprint fingerprint,
    String recaptchaValue
) {
}
