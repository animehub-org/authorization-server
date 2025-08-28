package org.animefoda.authorizationserver.entities.usersession;

import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.UUID;

@Embeddable
@Getter
@Setter
public class UserSessionEmbeddedKey implements Serializable {
    private UUID userId;
    private UUID sessionId;
}
