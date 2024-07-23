package com.tosan.tools.tencryptor.algorithm;

import com.tosan.tools.tencryptor.util.EncryptionUtil;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author soltanmohammadi
 * @since 12/26/2015
 */
public class DefaultAlgorithmEncryption implements AlgorithmEncryption {

    @Override
    public byte[] encrypt(String text, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec, String algorithm) {
        String encryptedText;
        if (ivParameterSpec == null) {
            encryptedText = EncryptionUtil.aesEncrypt(text, EncryptionUtil.ivGenerator(), secretKey, algorithm);
            return encryptedText.getBytes();
        } else {
            return EncryptionUtil.aesEncryptByIvParameter(text, ivParameterSpec, secretKey, algorithm);
        }
    }

    @Override
    public String decrypt(byte[] encrypted, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec, String algorithm)
            throws IllegalBlockSizeException {
        if (ivParameterSpec == null) {
            return EncryptionUtil.aesDecrypt(new String(encrypted), secretKey, algorithm);
        } else {
            return EncryptionUtil.aesDecryptByIvParameter(encrypted, secretKey, ivParameterSpec, algorithm);
        }
    }
}
