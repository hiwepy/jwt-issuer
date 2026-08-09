package io.github.easy4j.jwt.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link NotObtainedJwtException}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("NotObtainedJwtException Tests")
class NotObtainedJwtExceptionTest {

    @Test
    @DisplayName("should create exception with default constructor")
    void shouldCreateWithDefaultConstructor() {
        NotObtainedJwtException exception = new NotObtainedJwtException();
        assertThat(exception).isNotNull();
        assertThat(exception).isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("should create exception with message")
    void shouldCreateWithMessage() {
        String message = "JWT not yet valid";
        NotObtainedJwtException exception = new NotObtainedJwtException(message);
        assertThat(exception.getMessage()).isEqualTo(message);
    }

    @Test
    @DisplayName("should create exception with cause")
    void shouldCreateWithCause() {
        Throwable cause = new RuntimeException("not yet valid");
        NotObtainedJwtException exception = new NotObtainedJwtException(cause);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("should create exception with message and cause")
    void shouldCreateWithMessageAndCause() {
        String message = "JWT not yet valid";
        Throwable cause = new RuntimeException("not yet valid");
        NotObtainedJwtException exception = new NotObtainedJwtException(message, cause);
        assertThat(exception.getMessage()).isEqualTo(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }
}
