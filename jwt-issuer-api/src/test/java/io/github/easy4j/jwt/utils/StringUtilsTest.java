package io.github.easy4j.jwt.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link StringUtils}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("StringUtils Tests")
class StringUtilsTest {

    @Test
    @DisplayName("should tokenize string by comma")
    void shouldTokenizeStringByComma() {
        String[] result = StringUtils.tokenizeToStringArray("a,b,c");
        assertThat(result).containsExactly("a", "b", "c");
    }

    @Test
    @DisplayName("should tokenize string with spaces around commas")
    void shouldTokenizeStringWithSpaces() {
        String[] result = StringUtils.tokenizeToStringArray("a , b , c");
        assertThat(result).hasSize(3);
    }

    @Test
    @DisplayName("should handle single value")
    void shouldHandleSingleValue() {
        String[] result = StringUtils.tokenizeToStringArray("single");
        assertThat(result).containsExactly("single");
    }

    @Test
    @DisplayName("should handle empty string")
    void shouldHandleEmptyString() {
        String[] result = StringUtils.tokenizeToStringArray("");
        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("should have correct delimiters constant")
    void shouldHaveCorrectDelimitersConstant() {
        assertThat(StringUtils.CONFIG_LOCATION_DELIMITERS).isEqualTo(",");
    }

    @Test
    @DisplayName("should extend org.apache.commons.lang3.StringUtils")
    void shouldExtendCommonsStringUtils() {
        assertThat(org.apache.commons.lang3.StringUtils.class.isAssignableFrom(StringUtils.class)).isTrue();
    }

    @Test
    @DisplayName("inherited isEmpty should work")
    void inheritedIsEmptyShouldWork() {
        assertThat(StringUtils.isEmpty(null)).isTrue();
        assertThat(StringUtils.isEmpty("")).isTrue();
        assertThat(StringUtils.isEmpty("abc")).isFalse();
    }

    @Test
    @DisplayName("inherited isNoneBlank should work")
    void inheritedIsNoneBlankShouldWork() {
        assertThat(StringUtils.isNoneBlank("abc")).isTrue();
        assertThat(StringUtils.isNoneBlank("  ")).isFalse();
    }

    @Test
    @DisplayName("inherited defaultIfBlank should work")
    void inheritedDefaultIfBlankShouldWork() {
        assertThat(StringUtils.defaultIfBlank(null, "default")).isEqualTo("default");
        assertThat(StringUtils.defaultIfBlank("", "default")).isEqualTo("default");
        assertThat(StringUtils.defaultIfBlank("value", "default")).isEqualTo("value");
    }
}
