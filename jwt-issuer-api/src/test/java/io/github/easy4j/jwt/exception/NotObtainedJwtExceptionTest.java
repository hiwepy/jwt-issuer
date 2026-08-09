package io.github.easy4j.jwt.exception;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
@DisplayName("NotObtainedJwtException Tests")
class NotObtainedJwtExceptionTest {
    @Test void shouldCreateWithDefaultConstructor() { assertThat(new NotObtainedJwtException()).isInstanceOf(JwtException.class); }
    @Test void shouldCreateWithMessage() { assertThat(new NotObtainedJwtException("msg").getMessage()).isEqualTo("msg"); }
    @Test void shouldCreateWithCause() { var c = new RuntimeException(); assertThat(new NotObtainedJwtException(c).getCause()).isEqualTo(c); }
    @Test void shouldCreateWithMessageAndCause() { var c = new RuntimeException(); assertThat(new NotObtainedJwtException("msg", c).getMessage()).isEqualTo("msg"); }
}
