package com.security.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.auth.dto.LoginRequest;
import com.security.auth.dto.RegisterRequest;
import com.security.auth.repository.UserRepository;
import com.security.auth.service.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        userRepository.clear();
        loginAttemptService.reset();
    }

    @Test
    @DisplayName("Should successfully register user via application/x-www-form-urlencoded")
    void testRegisterSuccess_FormUrlEncoded() throws Exception {
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "test@example.com")
                        .param("password", "mypassword123"))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully."));
    }

    @Test
    @DisplayName("Should successfully register user via application/json")
    void testRegisterSuccess_Json() throws Exception {
        RegisterRequest request = new RegisterRequest("jsonuser@example.com", "securePass123");

        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully."));
    }

    @Test
    @DisplayName("Should reject registration when email already exists (Conflict / 409)")
    void testRegisterDuplicateEmail() throws Exception {
        // First registration
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "duplicate@example.com")
                        .param("password", "password123"))
                .andExpect(status().isOk());

        // Duplicate registration attempt
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "duplicate@example.com")
                        .param("password", "anotherPassword"))
                .andExpect(status().isConflict())
                .andExpect(content().string(containsString("Email is already registered.")));
    }

    @Test
    @DisplayName("Should reject registration with invalid email format (400 Bad Request)")
    void testRegisterInvalidEmail() throws Exception {
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "not-a-valid-email")
                        .param("password", "validPassword123"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Invalid email format")));
    }

    @Test
    @DisplayName("Should reject registration with short password (< 8 chars) (400 Bad Request)")
    void testRegisterShortPassword() throws Exception {
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "valid@example.com")
                        .param("password", "short"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Password must be between 8 and 128 characters")));
    }

    @Test
    @DisplayName("Should successfully login with valid credentials via form-urlencoded")
    void testLoginSuccess_FormUrlEncoded() throws Exception {
        // Register first
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "loginuser@example.com")
                        .param("password", "mypassword123"))
                .andExpect(status().isOk());

        // Login
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "loginuser@example.com")
                        .param("password", "mypassword123"))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful"));
    }

    @Test
    @DisplayName("Should successfully login with valid credentials via JSON")
    void testLoginSuccess_Json() throws Exception {
        // Register first
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest("jsonlogin@example.com", "mypassword123"))))
                .andExpect(status().isOk());

        // Login via JSON
        LoginRequest loginRequest = new LoginRequest("jsonlogin@example.com", "mypassword123");
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful"));
    }

    @Test
    @DisplayName("Should support case-insensitive email comparison during login")
    void testCaseInsensitiveLogin() throws Exception {
        // Register with uppercase
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "CaseTest@Example.COM")
                        .param("password", "mypassword123"))
                .andExpect(status().isOk());

        // Login with lowercase
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "casetest@example.com")
                        .param("password", "mypassword123"))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful"));
    }

    @Test
    @DisplayName("Should reject login with wrong password (401 Unauthorized)")
    void testLoginWrongPassword() throws Exception {
        // Register user
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "wrongpass@example.com")
                        .param("password", "correctPassword123"))
                .andExpect(status().isOk());

        // Attempt login with incorrect password
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "wrongpass@example.com")
                        .param("password", "incorrectPassword"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("Invalid email or password.")));
    }

    @Test
    @DisplayName("Should reject login for non-existent user with same message (401 Unauthorized)")
    void testLoginUserNotFound() throws Exception {
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", "nonexistent@example.com")
                        .param("password", "anyPassword123"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("Invalid email or password.")));
    }

    @Test
    @DisplayName("Should lock account after 5 consecutive failed login attempts (429 Too Many Requests)")
    void testAccountLockoutAfterMaxFailedAttempts() throws Exception {
        String testEmail = "lockout@example.com";

        // Register user
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", testEmail)
                        .param("password", "correctPassword123"))
                .andExpect(status().isOk());

        // Perform 4 failed attempts (should return 401 Unauthorized)
        for (int i = 0; i < 4; i++) {
            mockMvc.perform(post("/login")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                            .param("email", testEmail)
                            .param("password", "wrongPassword" + i))
                    .andExpect(status().isUnauthorized());
        }

        // 5th failed attempt causes lockout
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", testEmail)
                        .param("password", "wrongPassword5"))
                .andExpect(status().isUnauthorized());

        // 6th attempt (even with correct password) must be rejected with 429 Too Many Requests
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("email", testEmail)
                        .param("password", "correctPassword123"))
                .andExpect(status().isTooManyRequests())
                .andExpect(content().string(containsString("temporarily locked")));
    }
}
