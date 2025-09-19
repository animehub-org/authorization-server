package org.animefoda.authorizationserver.entities.role;

import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RoleService {

    private final RoleRepository repo;

    public RoleService(RoleRepository repo) {
        this.repo = repo;
    }

    public Optional<Role> findByName(RoleName name){
        return this.repo.findByName(name);
    }

    public boolean existsByName(RoleName name){
        return this.repo.existsByName(name);
    }

    public void save(Role role){
        this.repo.save(role);
    }
}
