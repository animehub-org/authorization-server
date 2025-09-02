package org.animefoda.authorizationserver.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.animefoda.authorizationserver.entities.role.Role;
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

@Service
public class JWTService {

    private String privateKeyPath;

    private String publicKeyPath;

    private final long refreshTokenExpirationMs = 100L * 60 * 60 * 30;

    private final RSAPrivateKey rsaPrivateKey;

    private final RSAPublicKey rsaPublicKey;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
//    @Bean
//    private JwtEncoder jwtEncoder() {
//        JWK jwk = new RSAKey.Builder(this.rsaPublicKey)
//                .privateKey(this.rsaPrivateKey)
//                .build();
//        ImmutableJWKSet<SecurityContext> jwks = new ImmutableJWKSet<SecurityContext>(new JWKSet(jwk));
//        return new NimbusJwtEncoder(jwks);
//    }

    public String generateAccessToken(UserSession session) {
        Instant now = Instant.now();
        final long accessTokenExpirationMs = 15 * 60 * 1000L;
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("self")
                .subject(session.getEmbeddedKey().getUserId().toString())
                .claim("sessionId", session.getEmbeddedKey().getSessionId())
                .claim("roles", session.getUser().getRoles().stream().map(Role::getName))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusMillis(accessTokenExpirationMs)))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(this.rsaPublicKey.getAlgorithm()).build(),
                claims
        );

        try{
            signedJWT.sign(new RSASSASigner(this.rsaPrivateKey));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Error signing JWT access token",e);
        }

    }

    public JWTService(
            @Value("${key.private.path}") String privateKeyPath,
            @Value("${key.public.path}") String publicKeyPath
    ) throws Exception {
        RsaLoaders loader = new RsaLoaders();
        this.rsaPrivateKey = loader.loadRSAPrivateKey(privateKeyPath);
        this.rsaPublicKey = loader.loadRSAPublicKey(publicKeyPath);
    }
}
