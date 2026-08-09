package io.github.easy4j.jwt.time;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link JwtTimeProvider}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("JwtTimeProvider Tests")
class JwtTimeProviderTest {

    @Test
    @DisplayName("should have default time provider constant")
    void shouldHaveDefaultTimeProviderConstant() {
        assertThat(JwtTimeProvider.DEFAULT_TIME_PROVIDER).isNotNull();
        assertThat(JwtTimeProvider.DEFAULT_TIME_PROVIDER).isInstanceOf(DefaultJwtTimeProvider.class);
    }

    @Test
    @DisplayName("default time provider should return valid time")
    void defaultTimeProviderShouldReturnValidTime() {
        long before = System.currentTimeMillis();
        long now = JwtTimeProvider.DEFAULT_TIME_PROVIDER.now();
        long after = System.currentTimeMillis();
        assertThat(now).isGreaterThanOrEqualTo(before).isLessThanOrEqualTo(after);
    }
}
