package com.tosan.tools.tencryptor.algorithm;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

/**
 * @author soltanmohammadi
 * @since 12/26/2015
 */
public interface AlgorithmEncryption {

    byte[] encrypt(String text, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec, String algorithm)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    String decrypt(byte[] encrypted, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec, String algorithm)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;
}
