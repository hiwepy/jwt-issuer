package io.github.easy4j.jwt.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link InvalidJwtToken}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("InvalidJwtToken Tests")
class InvalidJwtTokenTest {

    @Test
    @DisplayName("should create exception with default constructor")
    void shouldCreateWithDefaultConstructor() {
        InvalidJwtToken exception = new InvalidJwtToken();
        assertThat(exception).isNotNull();
        assertThat(exception).isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("should create exception with message")
    void shouldCreateWithMessage() {
        String message = "Invalid JWT token";
        InvalidJwtToken exception = new InvalidJwtToken(message);
        assertThat(exception.getMessage()).isEqualTo(message);
    }

    @Test
    @DisplayName("should create exception with cause")
    void shouldCreateWithCause() {
        Throwable cause = new RuntimeException("invalid");
        InvalidJwtToken exception = new InvalidJwtToken(cause);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("should create exception with message and cause")
    void shouldCreateWithMessageAndCause() {
        String message = "Invalid JWT token";
        Throwable cause = new RuntimeException("invalid");
        InvalidJwtToken exception = new InvalidJwtToken(message, cause);
        assertThat(exception.getMessage()).isEqualTo(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }
}
