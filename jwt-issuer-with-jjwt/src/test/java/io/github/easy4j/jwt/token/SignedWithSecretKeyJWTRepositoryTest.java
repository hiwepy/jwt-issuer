package io.github.easy4j.jwt.token;

import java.security.Key;
import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import io.github.easy4j.jwt.JwtPayload;
import io.github.easy4j.jwt.exception.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SignedWithSecretKeyJWTRepository Tests")
class SignedWithSecretKeyJWTRepositoryTest {
    private SignedWithSecretKeyJWTRepository repo;
    private Key key;
    @BeforeEach void setUp() { repo = new SignedWithSecretKeyJWTRepository(); key = Keys.secretKeyFor(SignatureAlgorithm.HS256); }
    @Test void shouldIssueJwtWithRoles() { assertThat(repo.issueJwt(key, UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", "HS256", 3600000)).isNotNull(); }
    @Test void shouldIssueJwtWithClaims() { Map<String, Object> c = new HashMap<>(); c.put("roles","admin"); assertThat(repo.issueJwt(key, UUID.randomUUID().toString(), "u", "i", "a", c, "HS256", 3600000)).isNotNull(); }
    @Test void shouldVerifyValidJwt() { String t = repo.issueJwt(key, UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", "HS256", 3600000); assertThat(repo.verify(key, t, true)).isTrue(); }
    @Test void shouldVerifyWithoutExpiryCheck() { String t = repo.issueJwt(key, UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", "HS256", 3600000); assertThat(repo.verify(key, t, false)).isTrue(); }
    @Test void shouldGetPayload() { String t = repo.issueJwt(key, UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", "HS256", 3600000); JwtPayload p = repo.getPlayload(key, t, true); assertThat(p.getSubject()).isEqualTo("u"); }
    @Test void shouldThrowForInvalidToken() { assertThatThrownBy(() -> repo.verify(key, "bad", true)).isInstanceOf(JwtException.class); }
    @Test void shouldSetAndGetClockSkew() { repo.setAllowedClockSkewSeconds(60); assertThat(repo.getAllowedClockSkewSeconds()).isEqualTo(60); }
    @Test void shouldSetAndGetCompressWith() { assertThat(repo.getCompressWith()).isNotNull(); }
    @Test void shouldSetAndGetClock() { assertThat(repo.getClock()).isNotNull(); }
    @Test void shouldIssueWithZeroPeriod() { assertThat(repo.issueJwt(key, UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", "HS256", 0)).isNotNull(); }
    @Test void shouldIssueWithNegativePeriod() { assertThat(repo.issueJwt(key, UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", "HS256", -1)).isNotNull(); }
    @Test void shouldIssueWithNullJwtId() { assertThat(repo.issueJwt(key, null, "u", "i", "a", "admin", "read", "HS256", 3600000)).isNotNull(); }
    @Test void shouldIssueWithNullAudience() { assertThat(repo.issueJwt(key, UUID.randomUUID().toString(), "u", "i", null, "admin", "read", "HS256", 3600000)).isNotNull(); }
    @Test void shouldIssueWithNullIssuer() { assertThat(repo.issueJwt(key, UUID.randomUUID().toString(), "u", null, "a", "admin", "read", "HS256", 3600000)).isNotNull(); }
}
