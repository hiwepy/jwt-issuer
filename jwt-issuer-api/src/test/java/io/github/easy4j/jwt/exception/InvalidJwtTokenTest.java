package io.github.easy4j.jwt.exception;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
@DisplayName("InvalidJwtToken Tests")
class InvalidJwtTokenTest {
    @Test void shouldCreateWithDefaultConstructor() { assertThat(new InvalidJwtToken()).isInstanceOf(JwtException.class); }
    @Test void shouldCreateWithMessage() { assertThat(new InvalidJwtToken("msg").getMessage()).isEqualTo("msg"); }
    @Test void shouldCreateWithCause() { var c = new RuntimeException(); assertThat(new InvalidJwtToken(c).getCause()).isEqualTo(c); }
    @Test void shouldCreateWithMessageAndCause() { var c = new RuntimeException(); assertThat(new InvalidJwtToken("msg", c).getMessage()).isEqualTo("msg"); }
}
