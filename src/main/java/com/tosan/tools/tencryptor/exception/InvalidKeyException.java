package com.tosan.tools.tencryptor.exception;

/**
 * @author Soltanmohammadi
 * @since 11/01/2015
 */
public class InvalidKeyException extends EncryptionException {

    public InvalidKeyException() {
    }

    public InvalidKeyException(String message) {
        super(message);
    }

    public InvalidKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidKeyException(Throwable cause) {
        super(cause);
    }
}
