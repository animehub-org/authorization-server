package org.animefoda.authorizationserver.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.animefoda.authorizationserver.entities.role.Role;
import org.animefoda.authorizationserver.entities.usersession.UserSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Date;

@Service
public class JWTService {

    @Value("${key.private.path}")
    private String privateKeyPath;

    @Value("${key.public.path}")
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

    public JWTService() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RsaLoaders loader = new RsaLoaders();
        this.rsaPrivateKey = loader.loadRSAPrivateKey(privateKeyPath);
        this.rsaPublicKey = loader.loadRSAPublicKey(this.publicKeyPath);
    }
}
