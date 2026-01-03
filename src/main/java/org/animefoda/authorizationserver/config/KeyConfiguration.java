package org.animefoda.authorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.animefoda.authorizationserver.security.RsaLoaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class KeyConfiguration {
    @Value("${key.private.path}")
    private String privateKeyPath;

    @Value("${key.public.path}")
    private String publicKeyPath;

    @Bean
    public RSAPrivateKey rsaPrivateKey() throws Exception {
        RsaLoaders loader = new RsaLoaders();
        return loader.loadRSAPrivateKey(privateKeyPath);
    }

    @Bean
    public RSAPublicKey rsaPublicKey() throws Exception {
        RsaLoaders loader = new RsaLoaders();
        return loader.loadRSAPublicKey(publicKeyPath);
    }

    // AQUI: O Bean do JwtDecoder que o Spring Security PROCURA
    @Bean
    public JwtDecoder jwtDecoder(RSAPublicKey rsaPublicKey) {
        return NimbusJwtDecoder.withPublicKey(rsaPublicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS384) // Aceita RS384
                .build();
    }

    // JWKSource exposto como Bean para o Authorization Server usar no endpoint
    // /oauth2/jwks
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey) {
        RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey)
                .privateKey(rsaPrivateKey)
                .keyID(java.util.UUID.randomUUID().toString())
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    // AQUI: O Bean do JwtEncoder (que você usará para gerar os tokens)
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
    // @Bean
    // public BCryptPasswordEncoder bCryptPasswordEncoder() {
    // return new BCryptPasswordEncoder();
    // }

    @Bean
    @Primary
    public PasswordEncoder passwordEncoder() {
        // Usa o DelegatingPasswordEncoder padrão. Ele reconhece {bcrypt}, {noop}, etc.
        // Isso garante que ele saiba lidar com o prefixo {noop} para o clientSecret.
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
