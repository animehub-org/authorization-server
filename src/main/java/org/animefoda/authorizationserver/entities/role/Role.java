package org.animefoda.authorizationserver.entities.role;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "role", schema = "users")
@Getter
@Setter
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column
    private RoleName name;

    public RoleDTO toDTO() {
        return new RoleDTO(
                this.id,
                this.name.name()
        );
    }
}
