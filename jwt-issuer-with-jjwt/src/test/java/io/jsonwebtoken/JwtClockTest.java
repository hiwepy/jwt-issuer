package io.jsonwebtoken;

import java.util.Date;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.easy4j.jwt.time.JwtTimeProvider;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link JwtClock}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("JwtClock Tests")
class JwtClockTest {

    @Test
    @DisplayName("should return current date")
    void shouldReturnCurrentDate() {
        JwtClock clock = new JwtClock();
        long before = System.currentTimeMillis();
        Date now = clock.now();
        long after = System.currentTimeMillis();
        assertThat(now.getTime()).isGreaterThanOrEqualTo(before).isLessThanOrEqualTo(after);
    }

    @Test
    @DisplayName("should implement Clock interface")
    void shouldImplementClockInterface() {
        JwtClock clock = new JwtClock();
        assertThat(clock).isInstanceOf(Clock.class);
    }

    @Test
    @DisplayName("should have default time provider")
    void shouldHaveDefaultTimeProvider() {
        JwtClock clock = new JwtClock();
        assertThat(clock.getTimeProvider()).isNotNull();
        assertThat(clock.getTimeProvider()).isInstanceOf(JwtTimeProvider.class);
    }

    @Test
    @DisplayName("should set and get time provider")
    void shouldSetAndGetTimeProvider() {
        JwtClock clock = new JwtClock();
        JwtTimeProvider customProvider = new JwtTimeProvider() {
            @Override
            public long now() {
                return 1000L;
            }
        };
        clock.setTimeProvider(customProvider);
        assertThat(clock.getTimeProvider()).isEqualTo(customProvider);
    }

    @Test
    @DisplayName("should use custom time provider for now()")
    void shouldUseCustomTimeProviderForNow() {
        JwtClock clock = new JwtClock();
        JwtTimeProvider customProvider = new JwtTimeProvider() {
            @Override
            public long now() {
                return 1000L;
            }
        };
        clock.setTimeProvider(customProvider);
        Date now = clock.now();
        assertThat(now.getTime()).isEqualTo(1000L);
    }
}
