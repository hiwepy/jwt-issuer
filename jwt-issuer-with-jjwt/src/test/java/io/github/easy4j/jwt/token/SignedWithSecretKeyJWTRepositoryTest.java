package io.github.easy4j.jwt.token;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.easy4j.jwt.JwtPayload;
import io.github.easy4j.jwt.exception.JwtException;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link SignedWithSecretKeyJWTRepository}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("SignedWithSecretKeyJWTRepository Tests")
class SignedWithSecretKeyJWTRepositoryTest {

    private SignedWithSecretKeyJWTRepository repository;
    private Key secretKey;

    @BeforeEach
    void setUp() {
        repository = new SignedWithSecretKeyJWTRepository();
        secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    @Test
    @DisplayName("should issue JWT with roles and permissions")
    void shouldIssueJwtWithRolesAndPermissions() {
        String token = repository.issueJwt(secretKey, UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin,user", "read,write", "HS256", 3600000);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should issue JWT with claims map")
    void shouldIssueJwtWithClaimsMap() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", "admin");
        claims.put("perms", "read");
        String token = repository.issueJwt(secretKey, UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                claims, "HS256", 3600000);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should verify valid JWT")
    void shouldVerifyValidJwt() {
        String token = repository.issueJwt(secretKey, UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", 3600000);
        boolean result = repository.verify(secretKey, token, true);
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("should verify JWT without expiry check")
    void shouldVerifyJwtWithoutExpiryCheck() {
        String token = repository.issueJwt(secretKey, UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", 3600000);
        boolean result = repository.verify(secretKey, token, false);
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("should get payload from JWT")
    void shouldGetPayloadFromJwt() {
        String token = repository.issueJwt(secretKey, UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", 3600000);
        JwtPayload payload = repository.getPlayload(secretKey, token, true);
        assertThat(payload).isNotNull();
        assertThat(payload.getSubject()).isEqualTo("testUser");
        assertThat(payload.getIssuer()).isEqualTo("issuer");
    }

    @Test
    @DisplayName("should throw exception for invalid token")
    void shouldThrowExceptionForInvalidToken() {
        assertThatThrownBy(() -> repository.verify(secretKey, "invalid-token", true))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("should set and get allowed clock skew seconds")
    void shouldSetAndGetAllowedClockSkewSeconds() {
        repository.setAllowedClockSkewSeconds(60);
        assertThat(repository.getAllowedClockSkewSeconds()).isEqualTo(60);
    }

    @Test
    @DisplayName("should set and get compress with")
    void shouldSetAndGetCompressWith() {
        assertThat(repository.getCompressWith()).isNotNull();
    }

    @Test
    @DisplayName("should set and get compression codec resolver")
    void shouldSetAndGetCompressionCodecResolver() {
        repository.setCompressionCodecResolver(null);
        assertThat(repository.getCompressionCodecResolver()).isNull();
    }

    @Test
    @DisplayName("should set and get clock")
    void shouldSetAndGetClock() {
        assertThat(repository.getClock()).isNotNull();
    }

    @Test
    @DisplayName("should issue JWT with zero period (no expiration)")
    void shouldIssueJwtWithZeroPeriod() {
        String token = repository.issueJwt(secretKey, UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", 0);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should issue JWT with negative period (no expiration)")
    void shouldIssueJwtWithNegativePeriod() {
        String token = repository.issueJwt(secretKey, UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", -1);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should issue JWT with null jwtId")
    void shouldIssueJwtWithNullJwtId() {
        String token = repository.issueJwt(secretKey, null,
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", 3600000);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should issue JWT with null audience")
    void shouldIssueJwtWithNullAudience() {
        String token = repository.issueJwt(secretKey, UUID.randomUUID().toString(),
                "testUser", "issuer", null,
                "admin", "read", "HS256", 3600000);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should issue JWT with null issuer")
    void shouldIssueJwtWithNullIssuer() {
        String token = repository.issueJwt(secretKey, UUID.randomUUID().toString(),
                "testUser", null, "audience",
                "admin", "read", "HS256", 3600000);
        assertThat(token).isNotNull().isNotEmpty();
    }
}
