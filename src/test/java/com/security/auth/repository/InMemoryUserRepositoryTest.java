package com.security.auth.repository;

import com.security.auth.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryUserRepositoryTest {

    private InMemoryUserRepository repository;

    @BeforeEach
    void setUp() {
        repository = new InMemoryUserRepository();
    }

    @Test
    @DisplayName("Should successfully save and retrieve user by email")
    void testSaveAndFindByEmail() {
        User user = new User("user@example.com", "$2a$12$hashedpassword");
        repository.save(user);

        Optional<User> found = repository.findByEmail("user@example.com");
        assertTrue(found.isPresent());
        assertEquals("user@example.com", found.get().getEmail());
        assertEquals("$2a$12$hashedpassword", found.get().getPasswordHash());
    }

    @Test
    @DisplayName("Should normalize email with whitespace and mixed casing")
    void testEmailNormalization() {
        User user = new User("  User.Test@Example.COM  ", "$2a$12$hashedpassword");
        repository.save(user);

        assertTrue(repository.existsByEmail("user.test@example.com"));
        assertTrue(repository.existsByEmail("USER.TEST@EXAMPLE.COM"));
        assertTrue(repository.existsByEmail("  User.Test@Example.COM  "));

        Optional<User> found = repository.findByEmail("user.test@example.com");
        assertTrue(found.isPresent());
    }

    @Test
    @DisplayName("Should return empty optional for non-existent email")
    void testFindByNonExistentEmail() {
        Optional<User> found = repository.findByEmail("notfound@example.com");
        assertTrue(found.isEmpty());
        assertFalse(repository.existsByEmail("notfound@example.com"));
    }

    @Test
    @DisplayName("Should clear all users")
    void testClear() {
        repository.save(new User("u1@example.com", "hash1"));
        repository.save(new User("u2@example.com", "hash2"));
        assertEquals(2, repository.count());

        repository.clear();
        assertEquals(0, repository.count());
    }
}
