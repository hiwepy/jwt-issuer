package io.jsonwebtoken;

import java.util.Date;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import io.github.easy4j.jwt.time.JwtTimeProvider;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtClock Tests")
class JwtClockTest {
    @Test void shouldReturnCurrentDate() { var c = new JwtClock(); long b = System.currentTimeMillis(); Date n = c.now(); long a = System.currentTimeMillis(); assertThat(n.getTime()).isGreaterThanOrEqualTo(b).isLessThanOrEqualTo(a); }
    @Test void shouldImplementClock() { assertThat(new JwtClock()).isInstanceOf(Clock.class); }
    @Test void shouldHaveDefaultTimeProvider() { assertThat(new JwtClock().getTimeProvider()).isNotNull(); }
    @Test void shouldSetAndGetTimeProvider() { var c = new JwtClock(); var tp = new JwtTimeProvider() { public long now() { return 1000L; } }; c.setTimeProvider(tp); assertThat(c.getTimeProvider()).isEqualTo(tp); }
    @Test void shouldUseCustomTimeProvider() { var c = new JwtClock(); c.setTimeProvider(() -> 1000L); assertThat(c.now().getTime()).isEqualTo(1000L); }
}
