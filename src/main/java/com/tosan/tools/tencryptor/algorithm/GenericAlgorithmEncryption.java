package com.tosan.tools.tencryptor.algorithm;

import com.tosan.tools.tencryptor.exception.EncryptionException;
import com.tosan.tools.tencryptor.exception.InvalidAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author soltanmohammadi
 * @since 12/26/2015
 */
public class GenericAlgorithmEncryption implements AlgorithmEncryption {
    private final Cipher cipher;

    public GenericAlgorithmEncryption(String algorithm) {
        try {
            cipher = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmException("could not initialize EncryptionUtility", e);
        } catch (NoSuchPaddingException e) {
            throw new EncryptionException("could not initialize EncryptionUtility", e);
        }
    }

    @Override
    public byte[] encrypt(String text, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec, String algorithm)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(text.getBytes());
    }

    @Override
    public String decrypt(byte[] encrypted, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec, String algorithm)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(encrypted));
    }
}
