package io.github.easy4j.jwt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link JwtClaims}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("JwtClaims Tests")
class JwtClaimsTest {

    @Test
    @DisplayName("should have correct default role")
    void shouldHaveCorrectDefaultRole() {
        assertThat(JwtClaims.DEFAULT_ROLE).isEqualTo("guest");
    }

    @Test
    @DisplayName("should have correct ID constant")
    void shouldHaveCorrectIdConstant() {
        assertThat(JwtClaims.ID).isEqualTo("id");
    }

    @Test
    @DisplayName("should have correct UID constant")
    void shouldHaveCorrectUidConstant() {
        assertThat(JwtClaims.UID).isEqualTo("uid");
    }

    @Test
    @DisplayName("should have correct UUID constant")
    void shouldHaveCorrectUuidConstant() {
        assertThat(JwtClaims.UUID).isEqualTo("uuid");
    }

    @Test
    @DisplayName("should have correct UNAME constant")
    void shouldHaveCorrectUnameConstant() {
        assertThat(JwtClaims.UNAME).isEqualTo("uname");
    }

    @Test
    @DisplayName("should have correct UKEY constant")
    void shouldHaveCorrectUkeyConstant() {
        assertThat(JwtClaims.UKEY).isEqualTo("ukey");
    }

    @Test
    @DisplayName("should have correct UCODE constant")
    void shouldHaveCorrectUcodeConstant() {
        assertThat(JwtClaims.UCODE).isEqualTo("ucode");
    }

    @Test
    @DisplayName("should have correct RID constant")
    void shouldHaveCorrectRidConstant() {
        assertThat(JwtClaims.RID).isEqualTo("rid");
    }

    @Test
    @DisplayName("should have correct RKEY constant")
    void shouldHaveCorrectRkeyConstant() {
        assertThat(JwtClaims.RKEY).isEqualTo("rkey");
    }

    @Test
    @DisplayName("should have correct RCODE constant")
    void shouldHaveCorrectRcodeConstant() {
        assertThat(JwtClaims.RCODE).isEqualTo("rcode");
    }

    @Test
    @DisplayName("should have correct SALT constant")
    void shouldHaveCorrectSaltConstant() {
        assertThat(JwtClaims.SALT).isEqualTo("salt");
    }

    @Test
    @DisplayName("should have correct SECRET constant")
    void shouldHaveCorrectSecretConstant() {
        assertThat(JwtClaims.SECRET).isEqualTo("secret");
    }

    @Test
    @DisplayName("should have correct ROLES constant")
    void shouldHaveCorrectRolesConstant() {
        assertThat(JwtClaims.ROLES).isEqualTo("roles");
    }

    @Test
    @DisplayName("should have correct PERMS constant")
    void shouldHaveCorrectPermsConstant() {
        assertThat(JwtClaims.PERMS).isEqualTo("perms");
    }

    @Test
    @DisplayName("should have correct PROFILE constant")
    void shouldHaveCorrectProfileConstant() {
        assertThat(JwtClaims.PROFILE).isEqualTo("profile");
    }

    @Test
    @DisplayName("should have correct BOUND constant")
    void shouldHaveCorrectBoundConstant() {
        assertThat(JwtClaims.BOUND).isEqualTo("bound");
    }

    @Test
    @DisplayName("should have correct INITIAL constant")
    void shouldHaveCorrectInitialConstant() {
        assertThat(JwtClaims.INITIAL).isEqualTo("initial");
    }

    @Test
    @DisplayName("should have correct VERIFY constant")
    void shouldHaveCorrectVerifyConstant() {
        assertThat(JwtClaims.VERIFY).isEqualTo("verify");
    }

    @Test
    @DisplayName("should have correct LONGITUDE constant")
    void shouldHaveCorrectLongitudeConstant() {
        assertThat(JwtClaims.LONGITUDE).isEqualTo("longitude");
    }

    @Test
    @DisplayName("should have correct LATITUDE constant")
    void shouldHaveCorrectLatitudeConstant() {
        assertThat(JwtClaims.LATITUDE).isEqualTo("latitude");
    }

    @Test
    @DisplayName("should have correct SIGN constant")
    void shouldHaveCorrectSignConstant() {
        assertThat(JwtClaims.SIGN).isEqualTo("sign");
    }
}
