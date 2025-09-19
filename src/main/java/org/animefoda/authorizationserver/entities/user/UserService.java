package org.animefoda.authorizationserver.entities.user;

import org.animefoda.authorizationserver.exception.AlreadyExistsException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public Optional<User> findByEmail(String email) {
        return repo.findByEmail(email);
    }

    public Optional<User> findByUsername(String username) {
        return this.repo.findByUsername(username);
    }

    public User save(User user) throws AlreadyExistsException {
        if(this.repo.findByEmail(user.getEmail()).isPresent()) {
            throw new AlreadyExistsException("Email");
        }
        if(this.repo.findByUsername(user.getUsername()).isPresent()) {
            throw new AlreadyExistsException("Username");
        }
        return this.repo.save(user);
    }
}
