package org.animefoda.authorizationserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

        @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:8080}")
        private String issuer;

        @Bean
        public AuthorizationServerSettings authorizationServerSettings() {
                return AuthorizationServerSettings.builder()
                                .issuer(issuer)
                                .build();
        }

        @Bean
        public RegisteredClientRepository registeredClientRepository() {

                // --- Configuração para o Client 1: FRONTEND (User Login Flow) ---
                // ID do cliente é o que o seu frontend vai usar para se identificar
                RegisteredClient frontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("my-client-frontend") // ID público
                                // Use {noop} para senhas em desenvolvimento, use BCrypt para produção!
                                .clientSecret("{noop}frontend-secret")
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

                                // Tipos de concessão para login de usuário e renovação de token
                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)

                                // URLs de redirecionamento após o login
                                .redirectUri("http://localhost:5173/authorized")

                                // Escopos (permissões) que o cliente pode solicitar
                                .scope("openid")
                                .scope("profile")
                                .scope("user.read")

                                // Configurações do Token
                                .tokenSettings(TokenSettings.builder()
                                                .accessTokenTimeToLive(Duration.ofMinutes(15)) // Access Token de 15
                                                                                               // minutos
                                                .refreshTokenTimeToLive(Duration.ofDays(7)) // Refresh Token de 7 dias
                                                .build())

                                // Requer consentimento do usuário
                                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                                .build();

                // --- Configuração para o Client 2: ADMIN API (Server-to-Server Flow) ---
                // Este é um serviço que precisa de um token para si mesmo, sem um usuário
                // logado
                RegisteredClient adminApiClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("admin-service-api")
                                .clientSecret("{noop}admin-secret-key")
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

                                // Tipo de concessão Client Credentials para comunicação Server-to-Server
                                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)

                                .scope("admin.write") // Permissão para escrita/administração
                                .tokenSettings(TokenSettings.builder()
                                                .accessTokenTimeToLive(Duration.ofHours(1)) // Token Server-to-Server de
                                                                                            // 1 hora
                                                .build())
                                .build();

                // Retorna um repositório em memória com ambos os clientes registrados
                return new InMemoryRegisteredClientRepository(frontendClient, adminApiClient);
        }
}
