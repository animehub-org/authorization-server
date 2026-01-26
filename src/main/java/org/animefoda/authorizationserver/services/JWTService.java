package org.animefoda.authorizationserver.services;

import entities.accessSession.AccessSession;
import entities.role.Role;
import entities.role.RoleName;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import entities.usersession.UserSession;
import org.animefoda.authorizationserver.security.RsaLoaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import services.UserSessionService;
import services.AccessService;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JWTService {
    private final UserSessionService userSessionService;
    private final AccessService accessService;

    @Getter
    private final long accessExpirationTimeMs;
    @Getter
    private final long refreshExpirationTimeMs;

    private final RSAPrivateKey rsaPrivateKey;
    private final RSAPublicKey rsaPublicKey;

    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    private String issuer;

    private String generateToken(Map<String, Object> claims, UserSession userSession, long expiration) {
        return Jwts.builder()
                .claims(claims)
                .issuer(issuer) // Adiciona o issuer configurado
                .subject(userSession.getUser().getId().toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(rsaPrivateKey) // Continua usando a chave privada
                .compact();
    }

    public String generateAccessToken(UserSession session) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("accessToken", UUID.randomUUID());
        List<String> roles = session.getUser().getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        if (session.getUser().isSuperUser())
            roles.add(RoleName.ROLE_SUPERUSER.toString());

        // 2. Adiciona as roles ao payload sob a chave 'roles' (ou 'scope')
        claims.put("roles", roles);
        // claims.put("superuser", session.getUser().isSuperUser());
        return this.generateToken(claims, session, this.accessExpirationTimeMs);
    }

    public String generateRefreshToken(UserSession session) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("refreshToken", session.getEmbeddedKey().getSessionId());
        return this.generateToken(claims, session, this.refreshExpirationTimeMs);
    }

    public boolean isAccessTokenValid(String accessToken) {
        UUID accessId = this.extractAccessId(accessToken);
        Optional<AccessSession> session = this.accessService.findByAccessId(accessId);
        return session.isPresent() && session.get().isActive();
    }

    public boolean isRefreshTokenValid(String refreshToken) {
        UUID refreshId = this.extractRefreshId(refreshToken);
        Optional<UserSession> session = this.userSessionService.findBySesssionId(refreshId);
        return session.isPresent() && session.get().isActive();
    }

    public UUID extractSubject(String accessToken) {
        return UUID.fromString(extractAllClaims(accessToken).getSubject());
    }

    public UUID extractAccessId(String accessToken) {
        return extractClaim(accessToken, claims -> claims.get("accessId", UUID.class));
    }

    public UUID extractRefreshId(String refreshToken) {
        return extractClaim(refreshToken, claims -> claims.get("refreshId", UUID.class));
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(this.rsaPublicKey) // Continua usando a chave pública
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public JWTService(
            @Value("${jwt.access.expiration}") long accessExpirationTimeMs,
            @Value("${jwt.refresh.expiration}") long refreshExpirationTimeMs,
            UserSessionService userSessionService,
            AccessService accessService,
            // As chaves agora são injetadas como Beans
            RSAPrivateKey rsaPrivateKey,
            RSAPublicKey rsaPublicKey) {
        this.userSessionService = userSessionService;
        this.accessService = accessService;
        this.accessExpirationTimeMs = accessExpirationTimeMs;
        this.refreshExpirationTimeMs = refreshExpirationTimeMs;

        // Atribui as chaves injetadas
        this.rsaPrivateKey = rsaPrivateKey;
        this.rsaPublicKey = rsaPublicKey;

        // A lógica de carregar as chaves (RsaLoaders) foi removida daqui
    }
}
