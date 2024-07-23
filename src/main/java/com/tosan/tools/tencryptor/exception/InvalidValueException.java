package com.tosan.tools.tencryptor.exception;

/**
 * @author Soltanmohammadi
 * @since 11/01/2015
 */
public class InvalidValueException extends EncryptionException {

    public InvalidValueException() {
    }

    public InvalidValueException(String message) {
        super(message);
    }

    public InvalidValueException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidValueException(Throwable cause) {
        super(cause);
    }
}
