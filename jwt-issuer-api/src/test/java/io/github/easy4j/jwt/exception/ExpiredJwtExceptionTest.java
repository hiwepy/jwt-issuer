package io.github.easy4j.jwt.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ExpiredJwtException Tests")
class ExpiredJwtExceptionTest {
    @Test void shouldCreateWithDefaultConstructor() { assertThat(new ExpiredJwtException()).isInstanceOf(JwtException.class); }
    @Test void shouldCreateWithMessage() { assertThat(new ExpiredJwtException("msg").getMessage()).isEqualTo("msg"); }
    @Test void shouldCreateWithCause() { var c = new RuntimeException(); assertThat(new ExpiredJwtException(c).getCause()).isEqualTo(c); }
    @Test void shouldCreateWithMessageAndCause() { var c = new RuntimeException(); assertThat(new ExpiredJwtException("msg", c).getMessage()).isEqualTo("msg"); }
}
