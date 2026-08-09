package io.github.easy4j.jwt.utils;

import java.util.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import io.github.easy4j.jwt.JwtPayload;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JJwtUtils Tests")
class JJwtUtilsTest {
    private SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    @Test void shouldCreateJwtBuilderWithClaims() { Map<String, Object> c = new HashMap<>(); c.put("roles","admin"); assertThat(JJwtUtils.jwtBuilder(UUID.randomUUID().toString(), "u", "i", "a", c, 3600000)).isNotNull(); }
    @Test void shouldCreateJwtBuilderWithRolesAndPerms() { assertThat(JJwtUtils.jwtBuilder(UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", 3600000)).isNotNull(); }
    @Test void shouldCreateParserBuilder() { assertThat(JJwtUtils.parserBuilder()).isNotNull(); }
    @Test void shouldConvertClaimsToPayload() throws Exception { Map<String, Object> c = new HashMap<>(); c.put("roles","admin"); String t = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(), "u", "i", "a", c, 3600000).signWith(key).compact(); JwtPayload p = JJwtUtils.payload(JJwtUtils.parseJWT(key, t)); assertThat(p.getSubject()).isEqualTo("u"); }
    @Test void shouldParseJwt() { String t = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", 3600000).signWith(key).compact(); assertThat(JJwtUtils.parseJWT(key, t).getSubject()).isEqualTo("u"); }
    @Test void shouldGenerateAccessToken() { var u = new JJwtUtils(); Map<String, Object> c = new HashMap<>(); assertThat(u.genAccessToken(key, "uid", "u", "i", "a", c, 3600000)).isNotNull(); }
    @Test void shouldGenerateRefreshToken() { var u = new JJwtUtils(); Map<String, Object> c = new HashMap<>(); assertThat(u.genRefreshToken(key, "uid", "u", "i", "a", c, 7200000)).isNotNull(); }
    @Test void shouldGetUsernameFromToken() { var u = new JJwtUtils(); String t = u.genAccessToken(key, "uid", "u", "i", "a", new HashMap<>(), 3600000); assertThat(u.getUsernameFromToken(key, t)).isEqualTo("u"); }
    @Test void shouldGetCreatedDate() { var u = new JJwtUtils(); String t = u.genAccessToken(key, "uid", "u", "i", "a", new HashMap<>(), 3600000); assertThat(u.getCreatedDateFromToken(key, t)).isNotNull(); }
    @Test void shouldGetExpirationDate() { var u = new JJwtUtils(); String t = u.genAccessToken(key, "uid", "u", "i", "a", new HashMap<>(), 3600000); assertThat(JJwtUtils.getExpirationDateFromToken(key, t)).isNotNull(); }
    @Test void shouldCheckIfTokenExpired() { var u = new JJwtUtils(); String t = u.genAccessToken(key, "uid", "u", "i", "a", new HashMap<>(), 3600000); assertThat(JJwtUtils.isTokenExpired(key, t)).isFalse(); }
    @Test void shouldCheckIfCreatedBeforeReset() { assertThat(JJwtUtils.isCreatedBeforeLastPasswordReset(null, null)).isFalse(); }
    @Test void shouldRefreshToken() { var u = new JJwtUtils(); String t = u.genAccessToken(key, "uid", "u", "i", "a", new HashMap<>(), 3600000); assertThat(u.refreshToken(key, t, 3600000)).isNotNull(); }
    @Test void shouldCheckIfTokenCanBeRefreshed() { var u = new JJwtUtils(); String t = u.genAccessToken(key, "uid", "u", "i", "a", new HashMap<>(), 3600000); assertThat(u.canTokenBeRefreshed(key, t, null)).isTrue(); }
    @Test void shouldHaveCorrectConstants() { assertThat(JJwtUtils.ROLE_REFRESH_TOKEN).isEqualTo("ROLE_REFRESH_TOKEN"); assertThat(JJwtUtils.CLAIM_KEY_USER_ID).isEqualTo("user_id"); }
    @Test void shouldCreateBuilderWithNullClaims() { assertThat(JJwtUtils.jwtBuilder(UUID.randomUUID().toString(), "u", "i", "a", null, 3600000)).isNotNull(); }
}
