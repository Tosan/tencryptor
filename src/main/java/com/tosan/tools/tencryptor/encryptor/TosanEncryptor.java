package com.tosan.tools.tencryptor.encryptor;

import com.tosan.tools.tencryptor.algorithm.AlgorithmEncryption;
import com.tosan.tools.tencryptor.algorithm.DefaultAlgorithmEncryption;
import com.tosan.tools.tencryptor.algorithm.DynamicAlgorithmEncryptionWithIV;
import com.tosan.tools.tencryptor.algorithm.GenericAlgorithmEncryption;
import com.tosan.tools.tencryptor.exception.EncryptionException;
import com.tosan.tools.tencryptor.exception.InvalidAlgorithmException;
import com.tosan.tools.tencryptor.exception.InvalidKeyException;
import com.tosan.tools.tencryptor.exception.InvalidValueException;
import com.tosan.tools.tencryptor.util.EncryptionStringUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Ajabkhani
 * @since 11/30/13
 */
public class TosanEncryptor implements Encryptor {
    public static final String AES_ALGORITHM = "AES";
    public static final String PKCS5_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String PKCS7_ALGORITHM = "AES/CBC/PKCS7Padding";
    private final String algorithm;
    private final Map<String, AlgorithmEncryption> cryptorAlgorithmsMap = new HashMap<>();
    private String key; //128-bit key
    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public TosanEncryptor(String key) {
        this(key, PKCS5_ALGORITHM);
    }

    public TosanEncryptor(String key, String algorithm) {
        this.key = key;
        this.algorithm = algorithm;
        if (algorithm.equals(PKCS5_ALGORITHM)) {
            cryptorAlgorithmsMap.put(PKCS5_ALGORITHM, new DefaultAlgorithmEncryption());
            secretKey = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
        } else if (algorithm.equals(PKCS7_ALGORITHM)) {
            cryptorAlgorithmsMap.put(algorithm, new DynamicAlgorithmEncryptionWithIV());
            secretKey = new SecretKeySpec(key.getBytes(), algorithm);
        } else {
            cryptorAlgorithmsMap.put(algorithm, new GenericAlgorithmEncryption(algorithm));
            secretKey = new SecretKeySpec(key.getBytes(), algorithm);
        }
    }

    public TosanEncryptor(String key, String ivParameter, String algorithm) {
        this(key, algorithm);
        ivParameterSpec = new IvParameterSpec(ivParameter.getBytes());
    }

    @Override
    public String encryptText(String text) {
        try {
            if (cryptorAlgorithmsMap.get(algorithm) == null) {
                throw new InvalidAlgorithmException("wrong algorithm name, could not encrypt text");
            }
            return encode(cryptorAlgorithmsMap.get(algorithm).encrypt(text, secretKey, ivParameterSpec, algorithm));
        } catch (java.security.InvalidKeyException e) {
            throw new InvalidKeyException("invalid key size, could not encrypt text", e);
        } catch (Exception e) {
            throw new EncryptionException("could not encrypt text", e);
        }
    }

    @Override
    public String decryptText(String text) {
        try {
            if (checkEmptyText(text)) return text;
            String chompedText = EncryptionStringUtil.chomp(text);
            return cryptorAlgorithmsMap.get(algorithm).decrypt(decode(chompedText), secretKey, ivParameterSpec, algorithm);
        } catch (BadPaddingException | java.security.InvalidKeyException e) {
            throw new InvalidKeyException("could not decrypt text with your key", e);
        } catch (Exception e) {
            throw new EncryptionException("could not decrypt text with your key", e);
        }
    }

    @Override
    public String decryptText(String key, String value) {
        try {
            if (checkEmptyText(value)) return value;
            String chompedValue = EncryptionStringUtil.chomp(value);
            return cryptorAlgorithmsMap.get(algorithm).decrypt(decode(chompedValue), secretKey, ivParameterSpec, algorithm);
        } catch (BadPaddingException | java.security.InvalidKeyException e) {
            throw new InvalidKeyException("could not decrypt text (" + key + ") with your key", e);
        } catch (Exception e) {
            throw new EncryptionException("could not decrypt text (" + key + ") with your key", e);
        }
    }

    @Override
    public void setKey(String key) {
        this.key = key;
        secretKey = new SecretKeySpec(this.key.getBytes(), algorithm);
    }

    private byte[] decode(String str) {
        return Base64.getDecoder().decode(str.getBytes());
    }

    private String encode(byte[] bytes) {
        byte[] encodedBytes = Base64.getEncoder().encode(bytes);
        return new String(encodedBytes);
    }

    private boolean checkEmptyText(String value) {
        if (isBlank(value)) {
            if (value == null) {
                throw new InvalidValueException("String value is null.");
            }
            return true;
        }
        return false;
    }

    public static boolean isBlank(final CharSequence cs) {
        final int strLen = cs == null ? 0 : cs.length();
        if (strLen == 0) {
            return true;
        }
        for (int i = 0; i < strLen; i++) {
            if (!Character.isWhitespace(cs.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
