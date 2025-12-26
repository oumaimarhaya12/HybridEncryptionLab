package com.tp;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAEncryption {

    public static byte[] encryptKey(SecretKey key, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(key.getEncoded());
    }

    public static SecretKey decryptKey(byte[] encryptedKey, PrivateKey privateKey, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] keyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(keyBytes, algorithm);
    }

    // Keep backward compatibility
    public static byte[] encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        return encryptKey(aesKey, publicKey);
    }

    public static SecretKey decryptAESKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        return decryptKey(encryptedKey, privateKey, "AES");
    }

    // New method for MAC keys
    public static SecretKey decryptMACKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        return decryptKey(encryptedKey, privateKey, "HmacSHA256");
    }
}