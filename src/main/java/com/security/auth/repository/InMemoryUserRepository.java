package com.security.auth.repository;

import com.security.auth.model.User;
import org.springframework.stereotype.Repository;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe In-Memory implementation of {@link UserRepository}.
 * Uses ConcurrentHashMap with normalized email keys (trimmed and lowercased)
 * to prevent case-sensitivity bypasses and race conditions during registration.
 */
@Repository
public class InMemoryUserRepository implements UserRepository {

    private final Map<String, User> userStorage = new ConcurrentHashMap<>();

    private String normalizeEmail(String email) {
        if (email == null) {
            return null;
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    @Override
    public User save(User user) {
        Objects.requireNonNull(user, "User cannot be null");
        String normalizedKey = normalizeEmail(user.getEmail());
        userStorage.put(normalizedKey, user);
        return user;
    }

    @Override
    public Optional<User> findByEmail(String email) {
        if (email == null) {
            return Optional.empty();
        }
        String normalizedKey = normalizeEmail(email);
        return Optional.ofNullable(userStorage.get(normalizedKey));
    }

    @Override
    public boolean existsByEmail(String email) {
        if (email == null) {
            return false;
        }
        String normalizedKey = normalizeEmail(email);
        return userStorage.containsKey(normalizedKey);
    }

    @Override
    public void deleteByEmail(String email) {
        if (email != null) {
            userStorage.remove(normalizeEmail(email));
        }
    }

    @Override
    public void clear() {
        userStorage.clear();
    }

    @Override
    public long count() {
        return userStorage.size();
    }
}
