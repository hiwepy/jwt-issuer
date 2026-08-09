package io.github.easy4j.jwt.time;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
@DisplayName("DefaultJwtTimeProvider Tests")
class DefaultJwtTimeProviderTest {
    @Test void shouldReturnCurrentTimeMillis() { var p = new DefaultJwtTimeProvider(); long b = System.currentTimeMillis(); long n = p.now(); long a = System.currentTimeMillis(); assertThat(n).isGreaterThanOrEqualTo(b).isLessThanOrEqualTo(a); }
    @Test void shouldImplementJwtTimeProvider() { assertThat(new DefaultJwtTimeProvider()).isInstanceOf(JwtTimeProvider.class); }
}
