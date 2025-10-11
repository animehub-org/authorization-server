package org.animefoda.authorizationserver.response;

import entities.user.UserDTO;

import java.io.Serializable;

public record TokenResponse(
    String accessToken,
    String refreshToken,
    Long expiresAt,
    UserDTO user
) implements Serializable {
}
