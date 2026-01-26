package org.animefoda.authorizationserver.config;

import org.animefoda.authorizationserver.security.ResourceOwnerPasswordAuthenticationToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import entities.usersession.UserSession;
import entities.role.Role;
import java.util.stream.Collectors;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

        @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:8080}")
        private String issuer;

        @Value("${oauth2.client.user-frontend.redirect-uri:http://localhost:5173}")
        private String userFrontendRedirectUri;

        @Value("${oauth2.client.admin-frontend.redirect-uri:http://localhost:5174}")
        private String adminFrontendRedirectUri;

        @Bean
        public AuthorizationServerSettings authorizationServerSettings() {
                return AuthorizationServerSettings.builder()
                                .issuer(issuer)
                                .build();
        }

        @Bean
        public OAuth2AuthorizationService authorizationService() {
                return new InMemoryOAuth2AuthorizationService();
        }

        @Bean
        public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder,
                        OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
                JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
                jwtGenerator.setJwtCustomizer(jwtCustomizer);
                OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
                OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
                return new DelegatingOAuth2TokenGenerator(
                                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
        }

        @Bean
        public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
                return context -> {
                        if (context.getPrincipal() instanceof UsernamePasswordAuthenticationToken) {
                                UsernamePasswordAuthenticationToken userAuth = (UsernamePasswordAuthenticationToken) context
                                                .getPrincipal();
                                if (userAuth.getDetails() instanceof UserSession) {
                                        UserSession session = (UserSession) userAuth.getDetails();

                                        // Add legacy claims
                                        context.getClaims().claim("accessToken", UUID.randomUUID().toString());
                                        context.getClaims().claim("roles",
                                                        session.getUser().getRoles().stream().map(Role::getName)
                                                                        .collect(Collectors.toList()));

                                        // Set Subject to User ID
                                        context.getClaims().subject(session.getUser().getId().toString());
                                }
                        }
                };
        }

        @Bean
        public RegisteredClientRepository registeredClientRepository() {

                // --- Client 1: USER FRONTEND (Público - para usuários normais) ---
                RegisteredClient userFrontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("user-frontend")
                                // Cliente PÚBLICO - sem secret
                                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)

                                // Grant types for user login
                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                .authorizationGrantType(ResourceOwnerPasswordAuthenticationToken.PASSWORD_GRANT_TYPE)

                                // Redirect URLs (configurável via env)
                                .redirectUri(userFrontendRedirectUri + "/authorized")
                                .redirectUri(userFrontendRedirectUri + "/callback")

                                // Scopes
                                .scope("openid")
                                .scope("profile")
                                .scope("user.read")

                                // Token settings
                                .tokenSettings(TokenSettings.builder()
                                                .accessTokenTimeToLive(Duration.ofHours(1))
                                                .refreshTokenTimeToLive(Duration.ofDays(30))
                                                .build())

                                .clientSettings(ClientSettings.builder()
                                                .requireAuthorizationConsent(false)
                                                .requireProofKey(false) // Não exige PKCE para password grant
                                                .build())
                                .build();

                // --- Client 2: ADMIN FRONTEND (Público - segurança via roles) ---
                RegisteredClient adminFrontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("admin-frontend")
                                // Cliente PÚBLICO - sem secret (segurança está nas roles do usuário)
                                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)

                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                .authorizationGrantType(ResourceOwnerPasswordAuthenticationToken.PASSWORD_GRANT_TYPE)

                                // Redirect URLs para admin (configurável via env)
                                .redirectUri(adminFrontendRedirectUri + "/authorized")
                                .redirectUri(adminFrontendRedirectUri + "/callback")

                                // Scopes
                                .scope("openid")
                                .scope("profile")
                                .scope("admin.read")
                                .scope("admin.write")

                                .tokenSettings(TokenSettings.builder()
                                                .accessTokenTimeToLive(Duration.ofHours(2))
                                                .refreshTokenTimeToLive(Duration.ofDays(30))
                                                .build())

                                .clientSettings(ClientSettings.builder()
                                                .requireAuthorizationConsent(false)
                                                .requireProofKey(false)
                                                .build())
                                .build();

                // --- Client 3: ADMIN API (Server-to-Server - mantém secret) ---
                RegisteredClient adminApiClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("admin-service-api")
                                .clientSecret("{noop}admin-secret-key")
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

                                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)

                                .scope("admin.write")
                                .tokenSettings(TokenSettings.builder()
                                                .accessTokenTimeToLive(Duration.ofHours(1))
                                                .build())
                                .build();

                return new InMemoryRegisteredClientRepository(userFrontendClient, adminFrontendClient, adminApiClient);
        }
}
