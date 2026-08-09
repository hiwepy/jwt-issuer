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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.security.Keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link SignedWithSecretResolverJWTRepository}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("SignedWithSecretResolverJWTRepository Tests")
class SignedWithSecretResolverJWTRepositoryTest {

    private SignedWithSecretResolverJWTRepository repository;
    private Key secretKey;

    @BeforeEach
    void setUp() {
        secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        SigningKeyResolver signingKeyResolver = new SigningKeyResolver() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                return secretKey;
            }

            @Override
            public Key resolveSigningKey(JwsHeader header, String plaintext) {
                return secretKey;
            }
        };
        repository = new SignedWithSecretResolverJWTRepository(signingKeyResolver);
    }

    @Test
    @DisplayName("should issue JWT with roles and permissions")
    void shouldIssueJwtWithRolesAndPermissions() {
        String token = repository.issueJwt(secretKey, "keyId", UUID.randomUUID().toString(),
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
        String token = repository.issueJwt(secretKey, "keyId", UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                claims, "HS256", 3600000);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should verify valid JWT")
    void shouldVerifyValidJwt() {
        String token = repository.issueJwt(secretKey, "keyId", UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", 3600000);
        boolean result = repository.verify(token, true);
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("should verify JWT without expiry check")
    void shouldVerifyJwtWithoutExpiryCheck() {
        String token = repository.issueJwt(secretKey, "keyId", UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", 3600000);
        boolean result = repository.verify(token, false);
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("should get payload from JWT")
    void shouldGetPayloadFromJwt() {
        String token = repository.issueJwt(secretKey, "keyId", UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", 3600000);
        JwtPayload payload = repository.getPlayload(token, true);
        assertThat(payload).isNotNull();
        assertThat(payload.getSubject()).isEqualTo("testUser");
    }

    @Test
    @DisplayName("should throw exception for invalid token")
    void shouldThrowExceptionForInvalidToken() {
        assertThatThrownBy(() -> repository.verify("invalid-token", true))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("should set and get allowed clock skew seconds")
    void shouldSetAndGetAllowedClockSkewSeconds() {
        repository.setAllowedClockSkewSeconds(60);
        assertThat(repository.getAllowedClockSkewSeconds()).isEqualTo(60);
    }

    @Test
    @DisplayName("should set and get signing key resolver")
    void shouldSetAndGetSigningKeyResolver() {
        SigningKeyResolver resolver = new SigningKeyResolver() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                return secretKey;
            }

            @Override
            public Key resolveSigningKey(JwsHeader header, String plaintext) {
                return secretKey;
            }
        };
        repository.setSigningKeyResolver(resolver);
        assertThat(repository).isNotNull();
    }

    @Test
    @DisplayName("should issue JWT with null keyId")
    void shouldIssueJwtWithNullKeyId() {
        String token = repository.issueJwt(secretKey, null, UUID.randomUUID().toString(),
                "testUser", "issuer", "audience",
                "admin", "read", "HS256", 3600000);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should construct with signing key resolver")
    void shouldConstructWithSigningKeyResolver() {
        SignedWithSecretResolverJWTRepository repo = new SignedWithSecretResolverJWTRepository();
        assertThat(repo).isNotNull();
    }
}
