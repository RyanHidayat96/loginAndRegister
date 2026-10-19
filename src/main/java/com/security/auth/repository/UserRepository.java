package com.security.auth.repository;

import com.security.auth.model.User;

import java.util.Optional;

/**
 * Repository interface defining persistence operations for User entity.
 */
public interface UserRepository {

    /**
     * Saves a user to the repository.
     *
     * @param user the user to persist
     * @return the persisted user
     */
    User save(User user);

    /**
     * Finds a user by their email address.
     *
     * @param email the email to search for
     * @return Optional containing the User if found, or empty Optional
     */
    Optional<User> findByEmail(String email);

    /**
     * Checks if a user with the given email already exists.
     *
     * @param email the email to check
     * @return true if exists, false otherwise
     */
    boolean existsByEmail(String email);

    /**
     * Deletes a user by their email.
     *
     * @param email the email of the user to delete
     */
    void deleteByEmail(String email);

    /**
     * Clears all users from the repository.
     */
    void clear();

    /**
     * Returns the total count of registered users.
     *
     * @return count of users
     */
    long count();
}
