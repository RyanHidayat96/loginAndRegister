package com.security.auth.service;

import com.security.auth.dto.LoginRequest;
import com.security.auth.dto.RegisterRequest;

/**
 * Service contract for user registration and authentication operations.
 */
public interface AuthService {

    /**
     * Registers a new user with secure password hashing.
     *
     * @param request registration credentials (email, password)
     * @return success message
     */
    String register(RegisterRequest request);

    /**
     * Authenticates a user against stored credentials.
     *
     * @param request login credentials (email, password)
     * @return success message
     */
    String login(LoginRequest request, String clientAddress);
}
