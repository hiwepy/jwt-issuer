package io.github.easy4j.jwt.exception;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
@DisplayName("IncorrectJwtException Tests")
class IncorrectJwtExceptionTest {
    @Test void shouldCreateWithDefaultConstructor() { assertThat(new IncorrectJwtException()).isInstanceOf(JwtException.class); }
    @Test void shouldCreateWithMessage() { assertThat(new IncorrectJwtException("msg").getMessage()).isEqualTo("msg"); }
    @Test void shouldCreateWithCause() { var c = new RuntimeException(); assertThat(new IncorrectJwtException(c).getCause()).isEqualTo(c); }
    @Test void shouldCreateWithMessageAndCause() { var c = new RuntimeException(); assertThat(new IncorrectJwtException("msg", c).getMessage()).isEqualTo("msg"); }
}
