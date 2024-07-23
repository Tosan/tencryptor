package com.tosan.tools.tencryptor.encryptor;

/**
 * @author Maleki
 * @since 5/31/2015
 */
public interface Encryptor {

    String encryptText(String text);

    String decryptText(String text);

    String decryptText(String key, String value);

    void setKey(String encryptionKey);
}
