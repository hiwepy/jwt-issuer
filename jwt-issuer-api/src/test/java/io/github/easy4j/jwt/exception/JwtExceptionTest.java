package io.github.easy4j.jwt.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link JwtException}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("JwtException Tests")
class JwtExceptionTest {

    @Test
    @DisplayName("should create exception with default constructor")
    void shouldCreateWithDefaultConstructor() {
        JwtException exception = new JwtException();
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isNull();
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("should create exception with message")
    void shouldCreateWithMessage() {
        String message = "JWT processing failed";
        JwtException exception = new JwtException(message);
        assertThat(exception.getMessage()).isEqualTo(message);
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("should create exception with cause")
    void shouldCreateWithCause() {
        Throwable cause = new RuntimeException("root cause");
        JwtException exception = new JwtException(cause);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("should create exception with message and cause")
    void shouldCreateWithMessageAndCause() {
        String message = "JWT processing failed";
        Throwable cause = new RuntimeException("root cause");
        JwtException exception = new JwtException(message, cause);
        assertThat(exception.getMessage()).isEqualTo(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("should be assignable to RuntimeException")
    void shouldBeAssignableToRuntimeException() {
        JwtException exception = new JwtException();
        assertThat(exception).isInstanceOf(RuntimeException.class);
    }
}
