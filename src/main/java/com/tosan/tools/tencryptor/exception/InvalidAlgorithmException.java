package com.tosan.tools.tencryptor.exception;

/**
 * @author Soltanmohammadi
 * @since 11/01/2015
 */
public class InvalidAlgorithmException extends EncryptionException {

    public InvalidAlgorithmException() {
    }

    public InvalidAlgorithmException(String message) {
        super(message);
    }

    public InvalidAlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidAlgorithmException(Throwable cause) {
        super(cause);
    }
}
