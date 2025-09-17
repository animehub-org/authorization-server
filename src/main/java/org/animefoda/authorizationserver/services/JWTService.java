package org.animefoda.authorizationserver.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import org.animefoda.authorizationserver.entities.role.Role;
import org.animefoda.authorizationserver.entities.role.RoleName;
import org.animefoda.authorizationserver.entities.usersession.UserSession;
import org.animefoda.authorizationserver.security.RsaLoaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
public class JWTService {

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

    public String generateAccessToken(UserSession session) {
        Instant now = Instant.now();
        List<RoleName> roles = session.getUser().getRoles().stream().map(Role::getName).toList();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("self")
                .subject(session.getEmbeddedKey().getUserId().toString())
                .claim("sessionId", session.getEmbeddedKey().getSessionId())
                .claim("roles", roles)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusMillis(this.accessExpirationTimeMs)))
                .build();

        return signAndSerialize(claims);
    }

    public String generateRefreshToken(UserSession session) {
        Instant now = Instant.now();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("self")
                .subject(session.getEmbeddedKey().getUserId().toString())
                .claim("sessionId", session.getEmbeddedKey().getSessionId())
                .claim("tokenType", "refresh") // Differentiates this token from the access token
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusMillis(this.refreshExpirationTimeMs)))
                .build();

        return signAndSerialize(claims);
    }

    // A private helper method to sign and serialize the JWT
    private String signAndSerialize(JWTClaimsSet claims) {
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(this.rsaPublicKey.getAlgorithm()).build(),
                claims
        );

        try {
            signedJWT.sign(new RSASSASigner(this.rsaPrivateKey));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Error signing JWT", e);
        }
    }

    public JWTService(
        @Value("${jwt.access.expiration}") long accessExpirationTimeMs,
        @Value("${jwt.refresh.expiration}") long refreshExpirationTimeMs,
        @Value("${key.private.path}") String privateKeyPath,
        @Value("${key.public.path}") String publicKeyPath
    ) throws Exception {
        this.accessExpirationTimeMs = accessExpirationTimeMs;
        this.refreshExpirationTimeMs = refreshExpirationTimeMs;

        RsaLoaders loader = new RsaLoaders();
        this.rsaPrivateKey = loader.loadRSAPrivateKey(privateKeyPath);
        this.rsaPublicKey = loader.loadRSAPublicKey(publicKeyPath);
    }
}
