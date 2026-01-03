package org.animefoda.authorizationserver.services;

import entities.role.Role;
import entities.role.RoleName;
import entities.user.User;
import entities.user.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import services.RoleService;

import java.util.*;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final RoleService roleService;

    public CustomOAuth2UserService(UserRepository userRepository, RoleService roleService) {
        this.userRepository = userRepository;
        this.roleService = roleService;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("given_name");
        String surname = oAuth2User.getAttribute("family_name");
        String googleId = oAuth2User.getAttribute("sub");

        if (email == null) {
            throw new OAuth2AuthenticationException("Email não encontrado no perfil do Google");
        }

        // Busca ou cria o usuário
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> createUserFromGoogle(email, name, surname, googleId));

        // Cria as authorities baseadas nas roles do usuário
        var authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());

        // Adiciona o userId aos atributos para uso posterior
        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
        attributes.put("userId", user.getId().toString());

        return new DefaultOAuth2User(authorities, attributes, "email");
    }

    private User createUserFromGoogle(String email, String name, String surname, String googleId) {
        Set<Role> roles = new HashSet<>();
        roleService.findByName(RoleName.ROLE_USER).ifPresent(roles::add);

        User newUser = User.builder()
                .email(email)
                .name(name != null ? name : "")
                .surname(surname != null ? surname : "")
                .username(generateUniqueUsername(email))
                .password("{noop}" + UUID.randomUUID()) // Senha aleatória (login via Google)
                .salt("")
                .superUser(false)
                .roles(roles)
                .build();

        return userRepository.save(newUser);
    }

    private String generateUniqueUsername(String email) {
        String baseUsername = email.split("@")[0];
        String username = baseUsername;
        int counter = 1;

        while (userRepository.findByUsername(username).isPresent()) {
            username = baseUsername + counter;
            counter++;
        }

        return username;
    }
}
