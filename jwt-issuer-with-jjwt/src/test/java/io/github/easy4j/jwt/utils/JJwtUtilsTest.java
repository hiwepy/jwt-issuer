package io.github.easy4j.jwt.utils;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.easy4j.jwt.JwtPayload;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link JJwtUtils}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("JJwtUtils Tests")
class JJwtUtilsTest {

    @Test
    @DisplayName("should create JwtBuilder with claims map")
    void shouldCreateJwtBuilderWithClaimsMap() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", "admin");
        claims.put("perms", "read");
        JwtBuilder builder = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(),
                "testUser", "issuer", "audience", claims, 3600000);
        assertThat(builder).isNotNull();
    }

    @Test
    @DisplayName("should create JwtBuilder with roles and permissions strings")
    void shouldCreateJwtBuilderWithRolesAndPerms() {
        JwtBuilder builder = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(),
                "testUser", "issuer", "audience", "admin", "read", 3600000);
        assertThat(builder).isNotNull();
    }

    @Test
    @DisplayName("should create JwtParserBuilder")
    void shouldCreateJwtParserBuilder() {
        JwtParserBuilder parserBuilder = JJwtUtils.parserBuilder();
        assertThat(parserBuilder).isNotNull();
    }

    @Test
    @DisplayName("should convert Claims to JwtPayload")
    void shouldConvertClaimsToJwtPayload() throws ParseException {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("roles", "admin");
        String token = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(),
                "testUser", "issuer", "audience", claimsMap, 3600000)
                .signWith(key).compact();
        Claims claims = JJwtUtils.parseJWT(key, token);
        JwtPayload payload = JJwtUtils.payload(claims);
        assertThat(payload).isNotNull();
        assertThat(payload.getSubject()).isEqualTo("testUser");
        assertThat(payload.getIssuer()).isEqualTo("issuer");
    }

    @Test
    @DisplayName("should parse JWT with secret key")
    void shouldParseJwtWithSecretKey() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String token = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(),
                "testUser", "issuer", "audience", "admin", "read", 3600000)
                .signWith(key).compact();
        Claims claims = JJwtUtils.parseJWT(key, token);
        assertThat(claims).isNotNull();
        assertThat(claims.getSubject()).isEqualTo("testUser");
    }

    @Test
    @DisplayName("should generate access token")
    void shouldGenerateAccessToken() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        JJwtUtils utils = new JJwtUtils();
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", "admin");
        String token = utils.genAccessToken(key, "uid", "testUser",
                "issuer", "audience", claims, 3600000);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should generate refresh token")
    void shouldGenerateRefreshToken() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        JJwtUtils utils = new JJwtUtils();
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", "admin");
        String token = utils.genRefreshToken(key, "uid", "testUser",
                "issuer", "audience", claims, 7200000);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should get username from token")
    void shouldGetUsernameFromToken() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        JJwtUtils utils = new JJwtUtils();
        Map<String, Object> claims = new HashMap<>();
        String token = utils.genAccessToken(key, "uid", "testUser",
                "issuer", "audience", claims, 3600000);
        String username = utils.getUsernameFromToken(key, token);
        assertThat(username).isEqualTo("testUser");
    }

    @Test
    @DisplayName("should get created date from token")
    void shouldGetCreatedDateFromToken() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        JJwtUtils utils = new JJwtUtils();
        Map<String, Object> claims = new HashMap<>();
        String token = utils.genAccessToken(key, "uid", "testUser",
                "issuer", "audience", claims, 3600000);
        assertThat(utils.getCreatedDateFromToken(key, token)).isNotNull();
    }

    @Test
    @DisplayName("should get expiration date from token")
    void shouldGetExpirationDateFromToken() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        JJwtUtils utils = new JJwtUtils();
        Map<String, Object> claims = new HashMap<>();
        String token = utils.genAccessToken(key, "uid", "testUser",
                "issuer", "audience", claims, 3600000);
        assertThat(JJwtUtils.getExpirationDateFromToken(key, token)).isNotNull();
    }

    @Test
    @DisplayName("should check if token is expired")
    void shouldCheckIfTokenIsExpired() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        JJwtUtils utils = new JJwtUtils();
        Map<String, Object> claims = new HashMap<>();
        String token = utils.genAccessToken(key, "uid", "testUser",
                "issuer", "audience", claims, 3600000);
        assertThat(JJwtUtils.isTokenExpired(key, token)).isFalse();
    }

    @Test
    @DisplayName("should check if created before last password reset")
    void shouldCheckIfCreatedBeforeLastPasswordReset() {
        assertThat(JJwtUtils.isCreatedBeforeLastPasswordReset(null, null)).isFalse();
    }

    @Test
    @DisplayName("should refresh token")
    void shouldRefreshToken() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        JJwtUtils utils = new JJwtUtils();
        Map<String, Object> claims = new HashMap<>();
        String token = utils.genAccessToken(key, "uid", "testUser",
                "issuer", "audience", claims, 3600000);
        String refreshed = utils.refreshToken(key, token, 3600000);
        assertThat(refreshed).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("should check if token can be refreshed")
    void shouldCheckIfTokenCanBeRefreshed() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        JJwtUtils utils = new JJwtUtils();
        Map<String, Object> claims = new HashMap<>();
        String token = utils.genAccessToken(key, "uid", "testUser",
                "issuer", "audience", claims, 3600000);
        Boolean canRefresh = utils.canTokenBeRefreshed(key, token, null);
        assertThat(canRefresh).isTrue();
    }

    @Test
    @DisplayName("should have correct claim key constants")
    void shouldHaveCorrectClaimKeyConstants() {
        assertThat(JJwtUtils.ROLE_REFRESH_TOKEN).isEqualTo("ROLE_REFRESH_TOKEN");
        assertThat(JJwtUtils.CLAIM_KEY_USER_ID).isEqualTo("user_id");
        assertThat(JJwtUtils.CLAIM_KEY_AUTHORITIES).isEqualTo("scope");
        assertThat(JJwtUtils.CLAIM_KEY_ACCOUNT_ENABLED).isEqualTo("enabled");
        assertThat(JJwtUtils.CLAIM_KEY_ACCOUNT_NON_LOCKED).isEqualTo("non_locked");
        assertThat(JJwtUtils.CLAIM_KEY_ACCOUNT_NON_EXPIRED).isEqualTo("non_expired");
    }

    @Test
    @DisplayName("should create JwtBuilder with null claims")
    void shouldCreateJwtBuilderWithNullClaims() {
        JwtBuilder builder = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(),
                "testUser", "issuer", "audience", null, 3600000);
        assertThat(builder).isNotNull();
    }

    @Test
    @DisplayName("should create JwtBuilder with null jwtId")
    void shouldCreateJwtBuilderWithNullJwtId() {
        JwtBuilder builder = JJwtUtils.jwtBuilder(null,
                "testUser", "issuer", "audience", "admin", "read", 3600000);
        assertThat(builder).isNotNull();
    }

    @Test
    @DisplayName("should create JwtBuilder with null audience")
    void shouldCreateJwtBuilderWithNullAudience() {
        JwtBuilder builder = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(),
                "testUser", "issuer", null, "admin", "read", 3600000);
        assertThat(builder).isNotNull();
    }

    @Test
    @DisplayName("should create JwtBuilder with null issuer")
    void shouldCreateJwtBuilderWithNullIssuer() {
        JwtBuilder builder = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(),
                "testUser", null, "audience", "admin", "read", 3600000);
        assertThat(builder).isNotNull();
    }
}
