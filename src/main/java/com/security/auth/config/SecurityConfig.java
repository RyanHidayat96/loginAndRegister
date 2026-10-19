package com.security.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Spring Security configuration.
 * Configures endpoints, headers, CORS, and stateless session management.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF for stateless REST endpoints
            .csrf(AbstractHttpConfigurer::disable)
            // Cross-origin access is disabled until an explicit trusted UI origin is configured.
            .cors(AbstractHttpConfigurer::disable)
            // Stateless session management (no session cookies created)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Endpoints authorization rules
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/register", "/login", "/error").permitAll()
                .anyRequest().authenticated()
            )
            // Security response headers for an API that never serves active content.
            .headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .contentTypeOptions(withDefaults())
                .cacheControl(withDefaults())
                .referrerPolicy(policy -> policy.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                .contentSecurityPolicy(policy -> policy.policyDirectives(
                        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                ))
            );

        return http.build();
    }
}
