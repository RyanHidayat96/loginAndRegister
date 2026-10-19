package com.security.auth;

import com.security.auth.dto.RegisterRequest;
import com.security.auth.model.User;
import com.security.auth.repository.UserRepository;
import com.security.auth.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class PasswordSecurityTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        userRepository.clear();
    }

    @Test
    @DisplayName("Password must be hashed with BCrypt and raw password should never be persisted")
    void testPasswordHashedWithBcrypt() {
        String rawPassword = "SuperSecretPassword123!";
        String email = "security@example.com";

        authService.register(new RegisterRequest(email, rawPassword));

        Optional<User> userOptional = userRepository.findByEmail(email);
        assertTrue(userOptional.isPresent());

        User user = userOptional.get();

        // 1. Raw password is NOT saved in user object
        assertNotEquals(rawPassword, user.getPasswordHash());

        // 2. Hash format corresponds to BCrypt ($2a$ or $2b$)
        assertTrue(user.getPasswordHash().startsWith("$2a$") || user.getPasswordHash().startsWith("$2b$"));

        // 3. PasswordEncoder confirms match
        assertTrue(passwordEncoder.matches(rawPassword, user.getPasswordHash()));

        // 4. Mismatched password fails
        assertFalse(passwordEncoder.matches("WrongPassword", user.getPasswordHash()));
    }
}
