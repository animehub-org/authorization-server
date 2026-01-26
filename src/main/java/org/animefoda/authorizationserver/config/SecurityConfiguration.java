package org.animefoda.authorizationserver.config;

import org.animefoda.authorizationserver.handler.OAuth2AuthenticationSuccessHandler;
import org.animefoda.authorizationserver.security.PublicClientAuthenticationConverter;
import org.animefoda.authorizationserver.security.PublicClientAuthenticationProvider;
import org.animefoda.authorizationserver.security.ResourceOwnerPasswordAuthenticationConverter;
import org.animefoda.authorizationserver.security.ResourceOwnerPasswordAuthenticationProvider;
import org.animefoda.authorizationserver.services.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
class SecurityConfiguration {

        private final CustomOAuth2UserService customOAuth2UserService;
        private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
        private final UserDetailsService userDetailsService;
        private final PasswordEncoder passwordEncoder;
        private final services.UserService userService;
        private final services.UserSessionService userSessionService;
        private final RegisteredClientRepository registeredClientRepository;

        SecurityConfiguration(
                        CustomOAuth2UserService customOAuth2UserService,
                        OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                        UserDetailsService userDetailsService,
                        PasswordEncoder passwordEncoder,
                        services.UserService userService,
                        services.UserSessionService userSessionService,
                        RegisteredClientRepository registeredClientRepository) {
                this.customOAuth2UserService = customOAuth2UserService;
                this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
                this.userDetailsService = userDetailsService;
                this.passwordEncoder = passwordEncoder;
                this.userService = userService;
                this.userSessionService = userSessionService;
                this.registeredClientRepository = registeredClientRepository;
        }

        // 1. Filtro do Authorization Server (Endpoints /oauth2/* e /jwks)
        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        public SecurityFilterChain authorizationServerSecurityFilterChain(
                        HttpSecurity http,
                        OAuth2AuthorizationService authorizationService,
                        OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

                OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

                http
                                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())

                                .with(authorizationServerConfigurer, configurer -> {
                                        configurer.oidc(Customizer.withDefaults());
                                        configurer.tokenIntrospectionEndpoint(Customizer.withDefaults());

                                        // Suporte para clientes públicos (sem secret)
                                        configurer.clientAuthentication(clientAuth -> clientAuth
                                                        .authenticationConverter(
                                                                        new PublicClientAuthenticationConverter())
                                                        .authenticationProvider(
                                                                        new PublicClientAuthenticationProvider(
                                                                                        registeredClientRepository)));

                                        // Register custom password grant at token endpoint
                                        configurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                                        .accessTokenRequestConverter(
                                                                        new ResourceOwnerPasswordAuthenticationConverter())
                                                        .authenticationProvider(
                                                                        new ResourceOwnerPasswordAuthenticationProvider(
                                                                                        authorizationService,
                                                                                        tokenGenerator,
                                                                                        userDetailsService,
                                                                                        passwordEncoder,
                                                                                        userService,
                                                                                        userSessionService)));
                                })

                                // Token endpoint precisa permitir requisições sem autenticação prévia
                                // (a autenticação é feita via credentials no body para Password Grant)
                                .authorizeHttpRequests(authorize -> authorize
                                                .requestMatchers("/oauth2/token", "/oauth2/jwks", "/.well-known/**")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                .csrf(AbstractHttpConfigurer::disable)
                                .cors(Customizer.withDefaults())

                                .exceptionHandling(exceptions -> exceptions
                                                .authenticationEntryPoint(
                                                                new LoginUrlAuthenticationEntryPoint("/login")));

                return http.build();
        }

        // 2. Filtro de Segurança Geral (Seus Controllers /login, /register, /g/** e
        // OAuth2 Login)
        @Bean
        public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(AbstractHttpConfigurer::disable)
                                .cors(Customizer.withDefaults())

                                .authorizeHttpRequests(authorize -> authorize
                                                .requestMatchers("/login", "/register", "/g/**", "/oauth2/**")
                                                .permitAll()
                                                .anyRequest().authenticated())

                                .oauth2Login(oauth2 -> oauth2
                                                .userInfoEndpoint(userInfo -> userInfo
                                                                .userService(customOAuth2UserService))
                                                .successHandler(oAuth2AuthenticationSuccessHandler))

                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

                return http.build();
        }
}
