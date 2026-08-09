package io.github.easy4j.jwt.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ExpiredJwtException}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("ExpiredJwtException Tests")
class ExpiredJwtExceptionTest {

    @Test
    @DisplayName("should create exception with default constructor")
    void shouldCreateWithDefaultConstructor() {
        ExpiredJwtException exception = new ExpiredJwtException();
        assertThat(exception).isNotNull();
        assertThat(exception).isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("should create exception with message")
    void shouldCreateWithMessage() {
        String message = "Token has expired";
        ExpiredJwtException exception = new ExpiredJwtException(message);
        assertThat(exception.getMessage()).isEqualTo(message);
    }

    @Test
    @DisplayName("should create exception with cause")
    void shouldCreateWithCause() {
        Throwable cause = new RuntimeException("expired");
        ExpiredJwtException exception = new ExpiredJwtException(cause);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("should create exception with message and cause")
    void shouldCreateWithMessageAndCause() {
        String message = "Token has expired";
        Throwable cause = new RuntimeException("expired");
        ExpiredJwtException exception = new ExpiredJwtException(message, cause);
        assertThat(exception.getMessage()).isEqualTo(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }
}
