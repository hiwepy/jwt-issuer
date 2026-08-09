package io.github.easy4j.jwt.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link IncorrectJwtException}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("IncorrectJwtException Tests")
class IncorrectJwtExceptionTest {

    @Test
    @DisplayName("should create exception with default constructor")
    void shouldCreateWithDefaultConstructor() {
        IncorrectJwtException exception = new IncorrectJwtException();
        assertThat(exception).isNotNull();
        assertThat(exception).isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("should create exception with message")
    void shouldCreateWithMessage() {
        String message = "Incorrect JWT format";
        IncorrectJwtException exception = new IncorrectJwtException(message);
        assertThat(exception.getMessage()).isEqualTo(message);
    }

    @Test
    @DisplayName("should create exception with cause")
    void shouldCreateWithCause() {
        Throwable cause = new RuntimeException("parse error");
        IncorrectJwtException exception = new IncorrectJwtException(cause);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("should create exception with message and cause")
    void shouldCreateWithMessageAndCause() {
        String message = "Incorrect JWT format";
        Throwable cause = new RuntimeException("parse error");
        IncorrectJwtException exception = new IncorrectJwtException(message, cause);
        assertThat(exception.getMessage()).isEqualTo(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }
}
