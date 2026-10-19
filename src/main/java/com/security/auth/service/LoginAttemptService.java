package com.security.auth.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service to protect against brute force login attacks.
 * Tracks consecutive failed login attempts and locks out the user temporarily.
 */
@Service
public class LoginAttemptService {

    public static final int MAX_ATTEMPTS = 5;
    public static final long LOCKOUT_DURATION_SECONDS = 15 * 60; // 15 minutes

    private final Map<String, AttemptInfo> attemptsCache = new ConcurrentHashMap<>();

    private static class AttemptInfo {
        int attempts;
        Instant lockoutUntil;

        AttemptInfo(int attempts, Instant lockoutUntil) {
            this.attempts = attempts;
            this.lockoutUntil = lockoutUntil;
        }
    }

    private String normalize(String key) {
        if (key == null) return "";
        return key.trim().toLowerCase(Locale.ROOT);
    }

    public void loginSucceeded(String key) {
        attemptsCache.remove(normalize(key));
    }

    public void loginFailed(String key) {
        String normalized = normalize(key);
        Instant now = Instant.now();

        attemptsCache.compute(normalized, (k, existing) -> {
            if (existing == null) {
                return new AttemptInfo(1, null);
            }

            // If previously locked but lockout expired, reset
            if (existing.lockoutUntil != null && now.isAfter(existing.lockoutUntil)) {
                return new AttemptInfo(1, null);
            }

            int newAttempts = existing.attempts + 1;
            Instant lockout = null;
            if (newAttempts >= MAX_ATTEMPTS) {
                lockout = now.plusSeconds(LOCKOUT_DURATION_SECONDS);
            }
            return new AttemptInfo(newAttempts, lockout);
        });
    }

    public boolean isBlocked(String key) {
        String normalized = normalize(key);
        AttemptInfo info = attemptsCache.get(normalized);
        if (info == null) {
            return false;
        }

        if (info.lockoutUntil != null) {
            if (Instant.now().isBefore(info.lockoutUntil)) {
                return true;
            } else {
                // Lockout period has passed; clear the record
                attemptsCache.remove(normalized);
                return false;
            }
        }
        return false;
    }

    public long getRemainingLockoutSeconds(String key) {
        String normalized = normalize(key);
        AttemptInfo info = attemptsCache.get(normalized);
        if (info != null && info.lockoutUntil != null) {
            long remaining = info.lockoutUntil.getEpochSecond() - Instant.now().getEpochSecond();
            return Math.max(0, remaining);
        }
        return 0;
    }

    public void reset() {
        attemptsCache.clear();
    }
}
