package org.animefoda.authorizationserver.entities.user;

import org.animefoda.authorizationserver.entities.role.RoleDTO;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

public record UserDTO(
    UUID id,
    String name,
    String surname,
    String username,
    Date birthDate,
    String email,
    boolean superUser,
    Set<RoleDTO> roles
)implements Serializable {
}
