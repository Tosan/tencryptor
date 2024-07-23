package com.tosan.tools.tencryptor.util;

import com.tosan.tools.tencryptor.exception.EncryptionException;
import com.tosan.tools.tencryptor.exception.InvalidAlgorithmException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author Hajihosseinkhani
 * @since 15/05/2022
 **/
public class HashUtil {
    private static final int SALT_LENGTH = 8;
    private static final String DEFAULT_ENCODING = "UTF-8";

    public static String getSHA2EncodingWithSalt(String clearTxt, String salt) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmException("SHA-2 digest implementation not included in classpath");
        }
        byte[] raw;
        try {
            md.update(salt.getBytes());
            raw = md.digest(clearTxt.getBytes(DEFAULT_ENCODING));
        } catch (UnsupportedEncodingException e) {
            throw new InvalidAlgorithmException("SHA-2 digest implementation not support UTF-8 encoding");
        }
        StringBuilder result = new StringBuilder();
        for (byte b : raw) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    public static String generateRandomSalt() {
        SecureRandom random;
        StringBuilder result = new StringBuilder();
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
            result.append(random.nextInt(9));
            for (int i = 0; i < HashUtil.SALT_LENGTH - 1; i++) {
                result.append(random.nextInt(9));
            }
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmException("The algorithm SHA1PRNG is not supported.");
        }
        return result.toString();
    }

    public static String generateSHA2HMACR(String data, String key) {
        try {
            Digest digest = new SHA256Digest();
            HMac hMac = new HMac(digest);
            hMac.init(new KeyParameter(key.getBytes(StandardCharsets.UTF_8)));
            byte[] hmacIn = data.getBytes();
            hMac.update(hmacIn, 0, hmacIn.length);
            byte[] hmacOut = new byte[hMac.getMacSize()];
            hMac.doFinal(hmacOut, 0);
            return bytesToHex(hmacOut);
        } catch (Exception e) {
            throw new EncryptionException("Exception occurred in generating HMAC, please ensure thar inputs are not null");
        }
    }

    public static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte h : hash) {
            String hex = Integer.toHexString(0xff & h);
            if (hex.length() < 2)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
