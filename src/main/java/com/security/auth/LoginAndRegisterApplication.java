package com.security.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

/**
 * Application entry point for User Authentication System.
 */
@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class LoginAndRegisterApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginAndRegisterApplication.class, args);
    }
}
