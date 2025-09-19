package org.animefoda.authorizationserver.entities.user;

import jakarta.persistence.*;
import lombok.Getter;
import org.animefoda.authorizationserver.entities.role.Role;
import org.animefoda.authorizationserver.entities.role.RoleDTO;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

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

    @Column(nullable = false, unique = true)
    private String username;

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

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_role",
        schema = "users",
        joinColumns = {@JoinColumn(name = "user_id")},
        inverseJoinColumns = {@JoinColumn(name = "role_id")}
    )
    private List<Role> roles = new ArrayList<>();

    public User(Date birthDate, String name, String surname, String username, String email, String password, String salt, boolean superuser, List<Role> roles) {
        this.birthDate = birthDate;
//        this.id = UUID.randomUUID();
        this.name = name;
        this.surname = surname;
        this.username = username;
        this.email = email;
        this.password = password;
        this.salt = salt;
        this.superuser = superuser;
        this.roles = roles;
    }

    public User() {}

    public UserDTO toUserDTO() {
        List<RoleDTO> roleDTOs = new ArrayList<>();
        if (this.roles != null) {
            roleDTOs = this.roles.stream()
                    .map(Role::toDTO)
                    .collect(Collectors.toList());
        }
        return new UserDTO(
                this.id,
                this.name,
                this.surname,
                this.username,
                this.birthDate,
                this.email,
                this.superuser,
                roleDTOs
        );
    }

    public boolean isLoginCorrect(String password, BCryptPasswordEncoder bCryptPasswordEncoder) {
        return bCryptPasswordEncoder.matches(password, this.password);
    }
}
