package org.animefoda.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;


@Configuration
class SecurityConfiguration {

    // 1. Filtro do Authorization Server (Endpoints /oauth2/* e /jwks)
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // Aplica a configuração principal do Authorization Server usando a sintaxe with()
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())

                // Personaliza o OIDC e JWKS DENTRO da aplicação do configurador
                .with(authorizationServerConfigurer, configurer -> {
                    configurer.oidc(Customizer.withDefaults());
                    configurer.tokenIntrospectionEndpoint(Customizer.withDefaults());
                })

                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)

                // Tratamento de exceção para endpoints de OAuth2
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    // 2. Filtro de Segurança Geral (Seus Controllers /login, /register, /g/**)
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Desabilita CSRF
                .cors(Customizer.withDefaults()) // Habilita o CORS

                .authorizeHttpRequests(authorize -> authorize
                        // Libera endpoints públicos
                        .requestMatchers("/login", "/register", "/g/**").permitAll()
                        // Protege todos os outros endpoints
                        .anyRequest().authenticated()
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }
}
