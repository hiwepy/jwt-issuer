package io.github.easy4j.jwt.token;
import java.security.Key;
import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import io.github.easy4j.jwt.JwtPayload;
import io.github.easy4j.jwt.exception.JwtException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
@DisplayName("SignedWithSecretResolverJWTRepository Tests")
class SignedWithSecretResolverJWTRepositoryTest {
    private SignedWithSecretResolverJWTRepository repo;
    private Key key;
    @BeforeEach void setUp() {
        key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        repo = new SignedWithSecretResolverJWTRepository(new SigningKeyResolver() {
            public Key resolveSigningKey(JwsHeader h, Claims c) { return key; }
            public Key resolveSigningKey(JwsHeader h, String p) { return key; }
            public Key resolveSigningKey(JwsHeader h, byte[] content) { return key; }
        });
    }
    @Test void shouldIssueJwtWithRoles() { assertThat(repo.issueJwt(key, "kid", UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", "HS256", 3600000)).isNotNull(); }
    @Test void shouldIssueJwtWithClaims() { Map<String, Object> c = new HashMap<>(); c.put("roles","admin"); assertThat(repo.issueJwt(key, "kid", UUID.randomUUID().toString(), "u", "i", "a", c, "HS256", 3600000)).isNotNull(); }
    @Test void shouldThrowForInvalidToken() { assertThatThrownBy(() -> repo.verify("bad", true)).isInstanceOf(JwtException.class); }
    @Test void shouldSetAndGetClockSkew() { repo.setAllowedClockSkewSeconds(60); assertThat(repo.getAllowedClockSkewSeconds()).isEqualTo(60); }
    @Test void shouldIssueWithNullKeyId() { assertThat(repo.issueJwt(key, null, UUID.randomUUID().toString(), "u", "i", "a", "admin", "read", "HS256", 3600000)).isNotNull(); }
    @Test void shouldConstructDefault() { assertThat(new SignedWithSecretResolverJWTRepository()).isNotNull(); }
}
