package com.security.auth.exception;

/**
 * Thrown when login fails due to incorrect email or password.
 * Using a unified exception avoids revealing whether the email or password was wrong.
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
