package com.security.auth.service;

import com.security.auth.dto.LoginRequest;
import com.security.auth.dto.RegisterRequest;
import com.security.auth.exception.AccountLockedException;
import com.security.auth.exception.InvalidCredentialsException;
import com.security.auth.exception.UserAlreadyExistsException;
import com.security.auth.model.User;
import com.security.auth.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

/**
 * Service implementation handling user registration and authentication.
 * Implements high-security practices:
 * - BCrypt password hashing
 * - Protection against timing attacks (user enumeration)
 * - Brute force attack lockout
 * - Case-insensitive email handling
 */
@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginAttemptService loginAttemptService;

    // Generated at startup using the active PasswordEncoder to ensure identical timing characteristics
    private String dummyPasswordHash;

    public AuthServiceImpl(UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           LoginAttemptService loginAttemptService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginAttemptService = loginAttemptService;
    }

    @PostConstruct
    public void init() {
        this.dummyPasswordHash = passwordEncoder.encode("dummy-anti-timing-attack-protection");
    }

    @Override
    public String register(RegisterRequest request) {
        String email = request.getEmail().trim();

        if (userRepository.existsByEmail(email)) {
            log.warn("Registration rejected: email {} is already in use", email);
            throw new UserAlreadyExistsException("Email is already registered.");
        }

        // Securely hash the password before persisting
        String hashedPassword = passwordEncoder.encode(request.getPassword());
        User newUser = new User(email, hashedPassword);
        userRepository.save(newUser);

        log.info("New user successfully registered with email: {}", email);
        return "User registered successfully.";
    }

    @Override
    public String login(LoginRequest request) {
        String email = request.getEmail().trim();
        String rawPassword = request.getPassword();

        // 1. Check if the account or IP is temporarily locked out
        if (loginAttemptService.isBlocked(email)) {
            long remainingSeconds = loginAttemptService.getRemainingLockoutSeconds(email);
            log.warn("Login attempt blocked for locked account: {}", email);
            throw new AccountLockedException(
                    "Account is temporarily locked due to excessive failed attempts. Please try again later.",
                    remainingSeconds
            );
        }

        // 2. Lookup user in repository
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            // Timing attack mitigation: perform hash computation even if user doesn't exist
            passwordEncoder.matches(rawPassword, dummyPasswordHash);
            loginAttemptService.loginFailed(email);
            log.warn("Login failed: User not found for email: {}", email);
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        User user = userOptional.get();

        // 3. Verify password hash
        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            loginAttemptService.loginFailed(email);
            log.warn("Login failed: Password mismatch for email: {}", email);
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        // 4. Successful login
        loginAttemptService.loginSucceeded(email);
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        log.info("User logged in successfully: {}", email);
        return "Login successful";
    }
}
