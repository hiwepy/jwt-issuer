package io.github.easy4j.jwt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtClaims Tests")
class JwtClaimsTest {
    @Test void shouldHaveCorrectDefaultRole() { assertThat(JwtClaims.DEFAULT_ROLE).isEqualTo("guest"); }
    @Test void shouldHaveCorrectIdConstant() { assertThat(JwtClaims.ID).isEqualTo("id"); }
    @Test void shouldHaveCorrectUidConstant() { assertThat(JwtClaims.UID).isEqualTo("uid"); }
    @Test void shouldHaveCorrectUuidConstant() { assertThat(JwtClaims.UUID).isEqualTo("uuid"); }
    @Test void shouldHaveCorrectUnameConstant() { assertThat(JwtClaims.UNAME).isEqualTo("uname"); }
    @Test void shouldHaveCorrectUkeyConstant() { assertThat(JwtClaims.UKEY).isEqualTo("ukey"); }
    @Test void shouldHaveCorrectUcodeConstant() { assertThat(JwtClaims.UCODE).isEqualTo("ucode"); }
    @Test void shouldHaveCorrectRidConstant() { assertThat(JwtClaims.RID).isEqualTo("rid"); }
    @Test void shouldHaveCorrectRkeyConstant() { assertThat(JwtClaims.RKEY).isEqualTo("rkey"); }
    @Test void shouldHaveCorrectRcodeConstant() { assertThat(JwtClaims.RCODE).isEqualTo("rcode"); }
    @Test void shouldHaveCorrectSaltConstant() { assertThat(JwtClaims.SALT).isEqualTo("salt"); }
    @Test void shouldHaveCorrectSecretConstant() { assertThat(JwtClaims.SECRET).isEqualTo("secret"); }
    @Test void shouldHaveCorrectRolesConstant() { assertThat(JwtClaims.ROLES).isEqualTo("roles"); }
    @Test void shouldHaveCorrectPermsConstant() { assertThat(JwtClaims.PERMS).isEqualTo("perms"); }
    @Test void shouldHaveCorrectProfileConstant() { assertThat(JwtClaims.PROFILE).isEqualTo("profile"); }
    @Test void shouldHaveCorrectBoundConstant() { assertThat(JwtClaims.BOUND).isEqualTo("bound"); }
    @Test void shouldHaveCorrectInitialConstant() { assertThat(JwtClaims.INITIAL).isEqualTo("initial"); }
    @Test void shouldHaveCorrectLongitudeConstant() { assertThat(JwtClaims.LONGITUDE).isEqualTo("longitude"); }
    @Test void shouldHaveCorrectLatitudeConstant() { assertThat(JwtClaims.LATITUDE).isEqualTo("latitude"); }
    @Test void shouldHaveCorrectSignConstant() { assertThat(JwtClaims.SIGN).isEqualTo("sign"); }
}
