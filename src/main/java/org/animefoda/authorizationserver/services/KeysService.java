package org.animefoda.authorizationserver.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

@Service
public class KeysService {
    private static final int KEY_SIZE = 2048;
    @Getter
    private PublicKey publicKey;
    @Getter
    private PrivateKey privateKey;

    private final ObjectMapper objectMapper;

    public KeysService() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KEY_SIZE);
        KeyPair keyPair = keyGen.generateKeyPair();

        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
        this.objectMapper = new ObjectMapper();
    }

    public String getPublicAsBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

//    public byte[] decrypt(byte[] encrypted) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//        Cipher cipher = Cipher.getInstance("RSA");
//
//        cipher.init(Cipher.DECRYPT_MODE,privateKey);
//        return cipher.doFinal(encrypted);
//    }
//    public String decryptBase64(String encryptedBase64) throws Exception {
//        // Decode the Base64 string into a byte array
//        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedBase64);
//
//        // Perform the decryption
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
//
//        // Convert the byte array to a String and return
//        return new String(decryptedBytes);
//    }
    public <T> T decryptAndDeserialize(String encryptedData, Class<T> clazz)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        String decryptedJson = new String(decryptedBytes);
        return objectMapper.readValue(decryptedJson,clazz);
    }
}
