package org.animefoda.authorizationserver.entities.role;

import java.io.Serializable;

public record RoleDTO(
    Long id,
    String name
) implements Serializable {
}
