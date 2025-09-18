package org.animefoda.authorizationserver.request;

import java.util.Date;

public record RegisterRequest(
    String username,
    String name,
    String surname,
    String email,
    Date birthDate,
    String password,
    String repeatPassword
) {
}
