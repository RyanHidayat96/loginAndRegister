package com.security.auth.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Limits a string by its UTF-8 byte length.
 * BCrypt accepts only the first 72 bytes of a password, so accepting longer
 * values would permit distinct passwords to authenticate as the same value.
 */
@Documented
@Constraint(validatedBy = Utf8ByteLengthValidator.class)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface Utf8ByteLength {

    String message() default "String exceeds maximum UTF-8 byte length";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    int max();
}
