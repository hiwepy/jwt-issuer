package io.github.easy4j.jwt.utils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
@DisplayName("StringUtils Tests")
class StringUtilsTest {
    @Test void shouldTokenizeStringByComma() { assertThat(StringUtils.tokenizeToStringArray("a,b,c")).containsExactly("a","b","c"); }
    @Test void shouldHandleSingleValue() { assertThat(StringUtils.tokenizeToStringArray("single")).containsExactly("single"); }
    @Test void shouldHaveCorrectDelimitersConstant() { assertThat(StringUtils.CONFIG_LOCATION_DELIMITERS).isEqualTo(","); }
    @Test void shouldExtendCommonsStringUtils() { assertThat(org.apache.commons.lang3.StringUtils.class.isAssignableFrom(StringUtils.class)).isTrue(); }
    @Test void inheritedIsEmptyShouldWork() { assertThat(StringUtils.isEmpty(null)).isTrue(); assertThat(StringUtils.isEmpty("")).isTrue(); assertThat(StringUtils.isEmpty("abc")).isFalse(); }
    @Test void inheritedDefaultIfBlankShouldWork() { assertThat(StringUtils.defaultIfBlank(null,"d")).isEqualTo("d"); assertThat(StringUtils.defaultIfBlank("","d")).isEqualTo("d"); assertThat(StringUtils.defaultIfBlank("v","d")).isEqualTo("v"); }
}
