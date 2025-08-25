package org.animefoda.authorizationserver.response;

public record TokenResponse(
    String accessToken,
    String refreshToken
) {
}
