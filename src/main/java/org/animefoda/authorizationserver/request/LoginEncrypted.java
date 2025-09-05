package org.animefoda.authorizationserver.request;

import java.io.Serializable;

public record LoginEncrypted(
    String encryptedInfo,
    String recaptchaToken
) implements Serializable {
}
