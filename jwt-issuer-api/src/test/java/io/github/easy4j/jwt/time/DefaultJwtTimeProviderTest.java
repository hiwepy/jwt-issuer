package io.github.easy4j.jwt.time;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link DefaultJwtTimeProvider}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("DefaultJwtTimeProvider Tests")
class DefaultJwtTimeProviderTest {

    @Test
    @DisplayName("should return current time millis")
    void shouldReturnCurrentTimeMillis() {
        DefaultJwtTimeProvider provider = new DefaultJwtTimeProvider();
        long before = System.currentTimeMillis();
        long now = provider.now();
        long after = System.currentTimeMillis();
        assertThat(now).isGreaterThanOrEqualTo(before).isLessThanOrEqualTo(after);
    }

    @Test
    @DisplayName("should implement JwtTimeProvider")
    void shouldImplementJwtTimeProvider() {
        DefaultJwtTimeProvider provider = new DefaultJwtTimeProvider();
        assertThat(provider).isInstanceOf(JwtTimeProvider.class);
    }
}
