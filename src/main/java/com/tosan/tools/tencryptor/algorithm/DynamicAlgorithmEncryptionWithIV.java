package com.tosan.tools.tencryptor.algorithm;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

/**
 * @author Ali Alimohammadi
 * @since 06/01/2019
 */
public class DynamicAlgorithmEncryptionWithIV extends DefaultAlgorithmEncryption {

    public DynamicAlgorithmEncryptionWithIV() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @Override
    public byte[] encrypt(String text, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec, String algorithm) {
        return super.encrypt(text, secretKey, ivParameterSpec, algorithm);
    }

    @Override
    public String decrypt(byte[] encrypted, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec, String algorithm)
            throws IllegalBlockSizeException {
        return super.decrypt(encrypted, secretKey, ivParameterSpec, algorithm);
    }
}
