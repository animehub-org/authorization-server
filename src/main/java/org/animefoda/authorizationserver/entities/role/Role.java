package org.animefoda.authorizationserver.entities.role;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name = "roles", schema = "users")
@Getter
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column
    private RoleName name;
}
