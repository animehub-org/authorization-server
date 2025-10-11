package org.animefoda.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // Permit access to specific public endpoints
                        .requestMatchers("/login", "/public/**", "/error").permitAll()
                        // Require authentication for all other requests
                        .anyRequest().authenticated()
                )
                // Add a login mechanism, like a form login
                .formLogin(Customizer.withDefaults());

        return http.build();
    }
}
