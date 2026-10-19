package com.security.auth.exception;

/**
 * Thrown when an attempt is made to register with an email that is already registered.
 */
public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
