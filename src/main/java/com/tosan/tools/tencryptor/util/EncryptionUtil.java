package com.tosan.tools.tencryptor.util;

import com.tosan.tools.tencryptor.exception.EncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;

/**
 * @author sajafari
 * @since 7/1/2015
 */
public class EncryptionUtil {
    private static final String DELIMITER = ":";

    public static KeyStore loadKeyStore(InputStream is, char[] password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(is, password);
            return keyStore;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new EncryptionException(e.getMessage(), e);
        }
    }

    @SuppressWarnings("unused")
    public static SecretKeySpec getAESSecretKey(KeyStore ks, char[] password) {
        try {
            String alias = "";
            Enumeration<String> en = ks.aliases();
            while (en.hasMoreElements()) {
                String aliases = en.nextElement();
                if ((ks.isKeyEntry(aliases) || ks.isCertificateEntry(aliases)) && aliases.equalsIgnoreCase("aes128")) {
                    alias = aliases;
                    break;
                }
            }
            return (SecretKeySpec) ks.getKey(alias, password);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new EncryptionException(e.getMessage(), e);
        }
    }

    public static IvParameterSpec ivGenerator() {
        //Create a random initialization vector
        SecureRandom random = new SecureRandom();
        byte[] randBytes = new byte[16];
        random.nextBytes(randBytes);
        return new IvParameterSpec(randBytes);
    }

    public static String aesEncrypt(String plainTxt, IvParameterSpec ivParameterSpec, SecretKeySpec keySpec, String algorithm) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
            byte[] cipherBytes = cipher.doFinal(plainTxt.getBytes(StandardCharsets.UTF_8));
            String cipherIV = new String(Base64.getEncoder().encode(cipherBytes));
            String iv = new String(Base64.getEncoder().encode(ivParameterSpec.getIV()));
            cipherIV += DELIMITER + iv;
            return cipherIV;
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("The '" + algorithm + "' algorithm is not supported.");
        } catch (NoSuchPaddingException e) {
            throw new EncryptionException("Padding is not available, " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new EncryptionException("The key for cryptography is invalid.");
        } catch (BadPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            throw new EncryptionException(e.getMessage());
        }
    }

    public static byte[] aesEncryptByIvParameter(String plainTxt, IvParameterSpec ivParameterSpec, SecretKeySpec keySpec, String algorithm) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
            return cipher.doFinal(plainTxt.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("The '" + algorithm + "' algorithm is not supported.");
        } catch (InvalidKeyException e) {
            throw new EncryptionException("The key for cryptography is invalid.");
        } catch (NoSuchPaddingException e) {
            throw new EncryptionException("Padding is not available, " + e.getMessage());
        } catch (InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            throw new EncryptionException(e.getMessage());
        }
    }

    public static String aesDecrypt(String encodeTxtWithIv, SecretKeySpec keySpec, String algorithm) {
        String[] encodedWithIvSplit = encodeTxtWithIv.split(DELIMITER);
        if (encodedWithIvSplit.length != 2) {
            throw new EncryptionException("Encrypted string does not contain " + DELIMITER + ".");
        }
        String encodeTxt = encodedWithIvSplit[0];
        String ivParameter = encodedWithIvSplit[1];
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(ivParameter));
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encodeTxt));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("The '" + algorithm + "' algorithm is not supported.");
        } catch (NoSuchPaddingException e) {
            throw new EncryptionException("Padding is not available, " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new EncryptionException("The key for cryptography is invalid.");
        } catch (BadPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            throw new EncryptionException(e.getMessage());
        }
    }

    public static String aesDecryptByIvParameter(byte[] encodeText, SecretKeySpec keySpec, IvParameterSpec ivParameterSpec, String algorithm) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
            byte[] original = cipher.doFinal(encodeText);
            return new String(original);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("The '" + algorithm + "' algorithm is not supported.");
        } catch (NoSuchPaddingException | BadPaddingException e) {
            throw new EncryptionException("Padding is not available, " + e.getMessage());
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new EncryptionException("The key for cryptography is invalid.");
        } catch (IllegalBlockSizeException e) {
            throw new EncryptionException("The Encryption Block Size is invalid.");
        }
    }

    public static String ecdhEncrypt(String text, String publicKeyEncoded, KeyStore keyStore, String privateKeyPassword, String alias) {
        return ECDHEncryptionUtil.encryptByAES(text, publicKeyEncoded, keyStore, privateKeyPassword, alias);
    }

    public static byte[] ecdhDecrypt(String EncodedText, String publicKeyEncoded, KeyStore keyStore, String privateKeyPassword, String alias) {
        return ECDHEncryptionUtil.decryptByAES(EncodedText, publicKeyEncoded, keyStore, privateKeyPassword, alias);
    }

    public static String generateSHA2HashWithSalt(String text, String salt) {
        return HashUtil.getSHA2EncodingWithSalt(text, salt);
    }

    public static String generateRandomSalt() {
        return HashUtil.generateRandomSalt();
    }

    public static String generateSH2HMAC(String data, String key) {
        return HashUtil.generateSHA2HMACR(data, key);
    }
}
