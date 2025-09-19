package org.animefoda.authorizationserver.loader;

import org.animefoda.authorizationserver.entities.role.Role;
import org.animefoda.authorizationserver.entities.role.RoleName;
import org.animefoda.authorizationserver.entities.role.RoleService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class RoleLoader implements CommandLineRunner {

    private final RoleService roleService;

    public RoleLoader(RoleService roleService) {
        this.roleService = roleService;
    }

    @Override
    public void run(String... args) throws Exception {
        RoleName[] roles = RoleName.values();
        for(RoleName roleName : roles) {
            if(!roleService.existsByName(roleName)) {
                Role role = new Role();
                role.setName(roleName);
                this.roleService.save(role);
            }
        }
    }
}
