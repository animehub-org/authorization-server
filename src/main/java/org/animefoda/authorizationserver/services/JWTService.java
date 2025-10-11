package org.animefoda.authorizationserver.services;

import entities.accessSession.AccessSession;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import entities.usersession.UserSession;
import org.animefoda.authorizationserver.security.RsaLoaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import services.UserSessionService;
import services.AccessService;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.function.Function;

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

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private String generateToken(Map<String, Object> claims, UserSession userSession, long expiration) {
        return Jwts.builder()
                .claims(claims)
                .subject(userSession.getUser().getId().toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(rsaPrivateKey)
                .compact();
    }

    public String generateAccessToken(UserSession session){
        Map<String, Object> claims = new HashMap<>();
        claims.put("accessToken", UUID.randomUUID());
        return this.generateToken(claims, session, this.accessExpirationTimeMs);
    }

    public String generateRefreshToken(UserSession session){
        Map<String, Object> claims = new HashMap<>();
        claims.put("refreshToken", session.getEmbeddedKey().getSessionId());
        return this.generateToken(claims, session, this.refreshExpirationTimeMs);
    }

    public boolean isAccessTokenValid(String accessToken){
        UUID accessId = this.extractAccessId(accessToken);
        Optional<AccessSession> session = this.accessService.findByAccessId(accessId);
        return session.isPresent() && session.get().isActive();
    }

    public boolean isRefreshTokenValid(String refreshToken) {
        UUID refreshId = this.extractRefreshId(refreshToken);
        Optional<UserSession> session = this.userSessionService.findBySesssionId(refreshId);
        return session.isPresent() && session.get().isActive();
    }

    private UUID extractAccessId(String accessToken){
        return extractClaim(accessToken, claims -> claims.get("accessId", UUID.class));
    }

    private UUID extractRefreshId(String refreshToken){
        return extractClaim(refreshToken, claims -> claims.get("refreshId", UUID.class));
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(this.rsaPublicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public JWTService(
        @Value("${jwt.access.expiration}") long accessExpirationTimeMs,
        @Value("${jwt.refresh.expiration}") long refreshExpirationTimeMs,
        @Value("${key.private.path}") String privateKeyPath,
        @Value("${key.public.path}") String publicKeyPath,
        UserSessionService userSessionService,
        AccessService accessService
    ) throws Exception {
        this.userSessionService = userSessionService;
        this.accessService = accessService;
        this.accessExpirationTimeMs = accessExpirationTimeMs;
        this.refreshExpirationTimeMs = refreshExpirationTimeMs;

        RsaLoaders loader = new RsaLoaders();
        this.rsaPrivateKey = loader.loadRSAPrivateKey(privateKeyPath);
        this.rsaPublicKey = loader.loadRSAPublicKey(publicKeyPath);
    }
}
