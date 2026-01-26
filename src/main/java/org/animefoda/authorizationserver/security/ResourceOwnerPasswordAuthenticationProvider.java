package org.animefoda.authorizationserver.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import services.UserService;
import services.UserSessionService;

import java.security.Principal;
import java.util.*;

/**
 * Authentication provider that validates username/password and generates OAuth2
 * tokens.
 */
public class ResourceOwnerPasswordAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final UserSessionService userSessionService;

    public ResourceOwnerPasswordAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            services.UserService userService,
            services.UserSessionService userSessionService) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
        this.userSessionService = userSessionService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ResourceOwnerPasswordAuthenticationToken passwordAuthentication = (ResourceOwnerPasswordAuthenticationToken) authentication;

        // Get client authentication
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrow(passwordAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        // Verify client supports password grant
        if (!registeredClient.getAuthorizationGrantTypes()
                .contains(ResourceOwnerPasswordAuthenticationToken.PASSWORD_GRANT_TYPE)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // Authenticate user
        String username = passwordAuthentication.getUsername();
        String password = passwordAuthentication.getPassword();

        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (Exception e) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid username or password", null));
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid username or password", null));
        }

        // Determine scopes
        Set<String> authorizedScopes = passwordAuthentication.getScopes();
        if (authorizedScopes == null || authorizedScopes.isEmpty()) {
            authorizedScopes = registeredClient.getScopes();
        } else {
            // Validate requested scopes are allowed
            for (String scope : authorizedScopes) {
                if (!registeredClient.getScopes().contains(scope)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
                }
            }
        }

        // Create user authentication
        UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(userDetails,
                null, userDetails.getAuthorities());

        // --- Custom Session Logic ---
        // Recuperar a entidade User para criar a sessão
        // O CustomUserDetailsService define o username como email, então buscamos por
        // email
        entities.user.User userEntity = userService.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "User entity not found", null)));

        entities.usersession.UserSession session = userSessionService.createSession(userEntity);

        // Extrair UserAgent e Fingerprint dos parâmetros adicionais
        if (passwordAuthentication.getAdditionalParameters().containsKey("userAgent")) {
            session.setUserAgent((String) passwordAuthentication.getAdditionalParameters().get("userAgent"));
        }
        if (passwordAuthentication.getAdditionalParameters().containsKey("fingerprint")) {
            session.setFingerprint((String) passwordAuthentication.getAdditionalParameters().get("fingerprint"));
        }

        userSessionService.save(session);

        // Anexar a sessão aos detalhes da autenticação para usar no TokenCustomizer
        userAuthentication.setDetails(session);
        // ---------------------------

        // Build token context
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(ResourceOwnerPasswordAuthenticationToken.PASSWORD_GRANT_TYPE)
                .authorizationGrant(passwordAuthentication);

        // Generate access token
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Failed to generate access token", null));
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                authorizedScopes);

        // Generate refresh token
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (generatedRefreshToken != null) {
                refreshToken = new OAuth2RefreshToken(
                        generatedRefreshToken.getTokenValue(),
                        generatedRefreshToken.getIssuedAt(),
                        generatedRefreshToken.getExpiresAt());
            }
        }

        // Build and save authorization
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(username)
                .authorizationGrantType(ResourceOwnerPasswordAuthenticationToken.PASSWORD_GRANT_TYPE)
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), userAuthentication);

        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken,
                    (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            ((ClaimAccessor) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        if (refreshToken != null) {
            authorizationBuilder.refreshToken(refreshToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();
        this.authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient, clientPrincipal, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ResourceOwnerPasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrow(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (authentication.getPrincipal() instanceof OAuth2ClientAuthenticationToken) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
