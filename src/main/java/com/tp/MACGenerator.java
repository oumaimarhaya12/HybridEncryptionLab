package com.tp;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MACGenerator {

    public static byte[] generateMAC(byte[] data, SecretKey macKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        return mac.doFinal(data);
    }

    public static boolean verifyMAC(byte[] data, byte[] receivedMAC, SecretKey macKey) throws Exception {
        byte[] calculatedMAC = generateMAC(data, macKey);
        return java.security.MessageDigest.isEqual(calculatedMAC, receivedMAC);
    }
}