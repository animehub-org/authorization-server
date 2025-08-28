package org.animefoda.authorizationserver.entities.user;

import jakarta.persistence.*;
import lombok.Getter;
import org.animefoda.authorizationserver.entities.role.Role;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Date;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "user", schema = "users")
@Getter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String surname;

    @Column(nullable = false,unique = true)
    private String email;

    @Column(nullable = false, name = "birthdate")
    private Date birthDate;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String salt;

    @Column(nullable = false)
    private boolean superuser;

    @JoinTable(
        name = "user_roles",
        schema = "users",
        joinColumns = {@JoinColumn(name = "user_id")},
        inverseJoinColumns = {@JoinColumn(name = "role_id")}
    )
    private List<Role> roles;

    public boolean isLoginCorrect(String password, BCryptPasswordEncoder bCryptPasswordEncoder) {
        return bCryptPasswordEncoder.matches(password, this.password);
    }
}
