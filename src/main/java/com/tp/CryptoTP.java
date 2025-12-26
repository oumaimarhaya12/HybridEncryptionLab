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

            // ===== 2. Generate MAC key =====
            SecretKey macKey = MACKeyGenerator.generateMACKey();
            System.out.println("MAC Key (Base64): " +
                    Base64.getEncoder().encodeToString(macKey.getEncoded()));

            // ===== 3. Generate RSA keys =====
            KeyPair rsaKeys = RSAKeyGenerator.generateRSAKeyPair();

            // ===== 4. Encrypt message using AES =====
            String message = "Winter is coming";
            byte[] iv = AESEncryption.generateIV();

            byte[] encryptedMessage = AESEncryption.encrypt(message, aesKey, iv);
            System.out.println("Encrypted Message: " +
                    Base64.getEncoder().encodeToString(encryptedMessage));

            // ===== 5. Generate MAC for the encrypted message =====
            byte[] mac = MACGenerator.generateMAC(encryptedMessage, macKey);
            System.out.println("MAC (Base64): " +
                    Base64.getEncoder().encodeToString(mac));

            // ===== 6. Encrypt AES key using RSA =====
            byte[] encryptedAESKey =
                    RSAEncryption.encryptAESKey(aesKey, rsaKeys.getPublic());
            System.out.println("Encrypted AES Key: " +
                    Base64.getEncoder().encodeToString(encryptedAESKey));

            // ===== 7. Encrypt MAC key using RSA =====
            byte[] encryptedMACKey =
                    RSAEncryption.encryptAESKey(macKey, rsaKeys.getPublic());
            System.out.println("Encrypted MAC Key: " +
                    Base64.getEncoder().encodeToString(encryptedMACKey));

            // ===== 8. Receiver side =====
            System.out.println("\n--- Receiver Side ---");

            // Decrypt AES key
            SecretKey recoveredAESKey =
                    RSAEncryption.decryptAESKey(encryptedAESKey, rsaKeys.getPrivate());

            // Decrypt MAC key
            SecretKey recoveredMACKey =
                    RSAEncryption.decryptAESKey(encryptedMACKey, rsaKeys.getPrivate());

            // Verify MAC before decryption
            boolean macVerified = MACGenerator.verifyMAC(encryptedMessage, mac, recoveredMACKey);
            System.out.println("MAC Verified: " + macVerified);

            if (!macVerified) {
                throw new SecurityException("MAC verification failed! Message may have been tampered with.");
            }

            // Decrypt message
            String decryptedMessage =
                    AESEncryption.decrypt(encryptedMessage, recoveredAESKey, iv);

            System.out.println("Decrypted Message: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}