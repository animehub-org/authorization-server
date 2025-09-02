package org.animefoda.authorizationserver.security;

import org.springframework.core.io.FileSystemResource;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

public class RsaLoaders {
    public RSAPrivateKey loadRSAPrivateKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileSystemResource resource = new FileSystemResource(path.replace("classpath:", ""));
        byte[] keyBytes = resource.getContentAsByteArray();
        String keyString = new String(keyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    public RSAPublicKey loadRSAPublicKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileSystemResource resource = new FileSystemResource(path.replace("classpath:", ""));
        byte[] keyBytes = resource.getContentAsByteArray();
        String keyString = new String(keyBytes)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
}
