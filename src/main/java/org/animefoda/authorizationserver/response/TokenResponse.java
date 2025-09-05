package org.animefoda.authorizationserver.response;

import java.io.Serializable;

public record TokenResponse(
    String accessToken,
    String refreshToken
) implements Serializable {
}
