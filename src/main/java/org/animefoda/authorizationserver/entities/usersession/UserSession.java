package org.animefoda.authorizationserver.entities.usersession;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.animefoda.authorizationserver.entities.user.User;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

@Table
@Entity
@Getter
@Setter
public class UserSession {
    @EmbeddedId
    private UserSessionEmbeddedKey embeddedKey;

    @MapsId("userId")
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "web_gl_vendor")
    private String webGlVendor;

    @Column(name = "web_gl_renderer")
    private String webGlRenderer;

    @Column(name = "time_zone")
    private String timeZone;
}