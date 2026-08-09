package io.github.easy4j.jwt.time;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtTimeProvider Tests")
class JwtTimeProviderTest {
    @Test void shouldHaveDefaultTimeProviderConstant() { assertThat(JwtTimeProvider.DEFAULT_TIME_PROVIDER).isNotNull().isInstanceOf(DefaultJwtTimeProvider.class); }
    @Test void defaultTimeProviderShouldReturnValidTime() { long b = System.currentTimeMillis(); long n = JwtTimeProvider.DEFAULT_TIME_PROVIDER.now(); long a = System.currentTimeMillis(); assertThat(n).isGreaterThanOrEqualTo(b).isLessThanOrEqualTo(a); }
}
