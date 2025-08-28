package org.animefoda.authorizationserver.entities.usersession;

import org.animefoda.authorizationserver.entities.user.User;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserSessionService {
    private final UserSessionRepository repo;

    public UserSessionService(UserSessionRepository repo) {
        this.repo = repo;
    }

    public void save(UserSession userSession){
        this.repo.save(userSession);
    }

    public void delete(UserSession userSession){
        this.repo.delete(userSession);
    }

    public Optional<UserSession> findByUserId(UUID userId) {
        return repo.findByIdUserId(userId);
    }

    public Optional<UserSession> findBySesssionId(UUID sessionId) {
        return repo.findByIdSessionId(sessionId);
    }

    public UserSession createSession(User user){
        UserSessionEmbeddedKey key = new UserSessionEmbeddedKey();
        key.setSessionId(UUID.randomUUID());
        key.setUserId(user.getId());

        UserSession session = new UserSession();
        session.setEmbeddedKey(key);
        session.setUser(user);
        session.setCreatedAt(Instant.now());
        return session;
    }
}
