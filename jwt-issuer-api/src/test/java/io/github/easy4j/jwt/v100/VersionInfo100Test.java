package io.github.easy4j.jwt.v100;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link VersionInfo100}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("VersionInfo100 Tests")
class VersionInfo100Test {

    @Test
    @DisplayName("should have correct VERSION constant")
    void shouldHaveCorrectVersion() {
        assertThat(VersionInfo100.VERSION).isEqualTo("1.0.x.20260630-SNAPSHOT");
    }

    @Test
    @DisplayName("should have correct BRANCH constant")
    void shouldHaveCorrectBranch() {
        assertThat(VersionInfo100.BRANCH).isEqualTo("feature/1.0.x");
    }

    @Test
    @DisplayName("should have correct BUILD_TIMESTAMP constant")
    void shouldHaveCorrectBuildTimestamp() {
        assertThat(VersionInfo100.BUILD_TIMESTAMP).isEqualTo("2026-08-06");
    }

    @Test
    @DisplayName("should have correct JAVA_TARGET constant")
    void shouldHaveCorrectJavaTarget() {
        assertThat(VersionInfo100.JAVA_TARGET).isEqualTo("1.8");
    }

    @Test
    @DisplayName("should be final class")
    void shouldBeFinalClass() {
        assertThat(VersionInfo100.class.getModifiers() & java.lang.reflect.Modifier.FINAL).isNotEqualTo(0);
    }
}
