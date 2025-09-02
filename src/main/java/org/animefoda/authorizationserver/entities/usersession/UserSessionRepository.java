package org.animefoda.authorizationserver.entities.usersession;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserSessionRepository extends JpaRepository<UserSession, UserSessionEmbeddedKey> {
    // Find a UserSession by its sessionId
    Optional<UserSession> findByEmbeddedKeySessionId(UUID sessionId);

    // Find a UserSession by its userId
    Optional<UserSession> findByEmbeddedKeyUserId(UUID userId);
}
