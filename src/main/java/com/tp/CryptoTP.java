package com.tp;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Base64;

public class CryptoTP {

    public static void main(String[] args) {

        try {
            // ===== 1. Generate AES key =====
            SecretKey aesKey = AESKeyGenerator.generateAESKey();
            System.out.println("AES Key (Base64): " +
                    Base64.getEncoder().encodeToString(aesKey.getEncoded()));

            // ===== 2. Generate RSA keys =====
            KeyPair rsaKeys = RSAKeyGenerator.generateRSAKeyPair();

            // ===== 3. Encrypt message using AES =====
            String message = "Winter is coming";
            byte[] iv = AESEncryption.generateIV();

            byte[] encryptedMessage = AESEncryption.encrypt(message, aesKey, iv);
            System.out.println("Encrypted Message: " +
                    Base64.getEncoder().encodeToString(encryptedMessage));

            // ===== 4. Encrypt AES key using RSA =====
            byte[] encryptedAESKey =
                    RSAEncryption.encryptAESKey(aesKey, rsaKeys.getPublic());

            System.out.println("Encrypted AES Key: " +
                    Base64.getEncoder().encodeToString(encryptedAESKey));

            // ===== 5. Receiver side =====

            // Decrypt AES key
            SecretKey recoveredAESKey =
                    RSAEncryption.decryptAESKey(encryptedAESKey, rsaKeys.getPrivate());

            // Decrypt message
            String decryptedMessage =
                    AESEncryption.decrypt(encryptedMessage, recoveredAESKey, iv);

            System.out.println("Decrypted Message: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
