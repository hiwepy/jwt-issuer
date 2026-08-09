package io.github.easy4j.jwt.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtException Tests")
class JwtExceptionTest {
    @Test void shouldCreateWithDefaultConstructor() { assertThat(new JwtException()).isNotNull(); }
    @Test void shouldCreateWithMessage() { assertThat(new JwtException("msg").getMessage()).isEqualTo("msg"); }
    @Test void shouldCreateWithCause() { var c = new RuntimeException(); assertThat(new JwtException(c).getCause()).isEqualTo(c); }
    @Test void shouldCreateWithMessageAndCause() { var c = new RuntimeException(); assertThat(new JwtException("msg", c).getMessage()).isEqualTo("msg"); }
    @Test void shouldBeAssignableToRuntimeException() { assertThat(new JwtException()).isInstanceOf(RuntimeException.class); }
}
