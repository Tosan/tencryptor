package com.tosan.tools.tencryptor.exception;

/**
 * @author Ali Alimohammadi
 * @since 04/08/2023
 */
public class EncryptionException extends RuntimeException {

    public EncryptionException() {
    }

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncryptionException(Throwable cause) {
        super(cause);
    }

}
