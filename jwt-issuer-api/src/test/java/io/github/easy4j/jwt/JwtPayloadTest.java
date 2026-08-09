package io.github.easy4j.jwt;

import java.util.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link JwtPayload}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@DisplayName("JwtPayload Tests")
class JwtPayloadTest {

    @Test
    @DisplayName("should set and get tokenId")
    void shouldSetAndGetTokenId() {
        JwtPayload payload = new JwtPayload();
        payload.setTokenId("token-123");
        assertThat(payload.getTokenId()).isEqualTo("token-123");
    }

    @Test
    @DisplayName("should set and get subject")
    void shouldSetAndGetSubject() {
        JwtPayload payload = new JwtPayload();
        payload.setSubject("user1");
        assertThat(payload.getSubject()).isEqualTo("user1");
    }

    @Test
    @DisplayName("should set and get clientName")
    void shouldSetAndGetClientName() {
        JwtPayload payload = new JwtPayload();
        payload.setClientName("Test User");
        assertThat(payload.getClientName()).isEqualTo("Test User");
    }

    @Test
    @DisplayName("should fallback clientName to claims uname")
    void shouldFallbackClientNameToClaimsUname() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.UNAME, "fallbackUser");
        payload.setClaims(claims);
        assertThat(payload.getClientName()).isEqualTo("fallbackUser");
    }

    @Test
    @DisplayName("should set and get issuer")
    void shouldSetAndGetIssuer() {
        JwtPayload payload = new JwtPayload();
        payload.setIssuer("issuer1");
        assertThat(payload.getIssuer()).isEqualTo("issuer1");
    }

    @Test
    @DisplayName("should set and get issuedAt")
    void shouldSetAndGetIssuedAt() {
        JwtPayload payload = new JwtPayload();
        Date now = new Date();
        payload.setIssuedAt(now);
        assertThat(payload.getIssuedAt()).isEqualTo(now);
    }

    @Test
    @DisplayName("should set and get expiration")
    void shouldSetAndGetExpiration() {
        JwtPayload payload = new JwtPayload();
        Date exp = new Date();
        payload.setExpiration(exp);
        assertThat(payload.getExpiration()).isEqualTo(exp);
    }

    @Test
    @DisplayName("should set and get notBefore")
    void shouldSetAndGetNotBefore() {
        JwtPayload payload = new JwtPayload();
        Date nbf = new Date();
        payload.setNotBefore(nbf);
        assertThat(payload.getNotBefore()).isEqualTo(nbf);
    }

    @Test
    @DisplayName("should set and get audience")
    void shouldSetAndGetAudience() {
        JwtPayload payload = new JwtPayload();
        List<String> audience = Arrays.asList("aud1", "aud2");
        payload.setAudience(audience);
        assertThat(payload.getAudience()).containsExactly("aud1", "aud2");
    }

    @Test
    @DisplayName("should return empty map when claims is null")
    void shouldReturnEmptyMapWhenClaimsIsNull() {
        JwtPayload payload = new JwtPayload();
        assertThat(payload.getClaims()).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("should set and get claims")
    void shouldSetAndGetClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put("key1", "value1");
        payload.setClaims(claims);
        assertThat(payload.getClaims()).containsEntry("key1", "value1");
    }

    @Test
    @DisplayName("should set and get host")
    void shouldSetAndGetHost() {
        JwtPayload payload = new JwtPayload();
        payload.setHost("192.168.1.1");
        assertThat(payload.getHost()).isEqualTo("192.168.1.1");
    }

    @Test
    @DisplayName("should get uid from claims when present")
    void shouldGetUidFromClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.UID, "uid-123");
        payload.setClaims(claims);
        assertThat(payload.getUid()).isEqualTo("uid-123");
    }

    @Test
    @DisplayName("should get uid from field when claims is null")
    void shouldGetUidFromField() {
        JwtPayload payload = new JwtPayload();
        payload.setUid("uid-456");
        assertThat(payload.getUid()).isEqualTo("uid-456");
    }

    @Test
    @DisplayName("should get uuid from claims when present")
    void shouldGetUuidFromClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.UUID, "uuid-123");
        payload.setClaims(claims);
        assertThat(payload.getUuid()).isEqualTo("uuid-123");
    }

    @Test
    @DisplayName("should get ukey from claims when present")
    void shouldGetUkeyFromClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.UKEY, "ukey-123");
        payload.setClaims(claims);
        assertThat(payload.getUkey()).isEqualTo("ukey-123");
    }

    @Test
    @DisplayName("should get ucode from claims when present")
    void shouldGetUcodeFromClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.UCODE, "ucode-123");
        payload.setClaims(claims);
        assertThat(payload.getUcode()).isEqualTo("ucode-123");
    }

    @Test
    @DisplayName("should get rid from claims when present")
    void shouldGetRidFromClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.RID, "rid-123");
        payload.setClaims(claims);
        assertThat(payload.getRid()).isEqualTo("rid-123");
    }

    @Test
    @DisplayName("should get rkey from claims when present")
    void shouldGetRkeyFromClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.RKEY, "rkey-123");
        payload.setClaims(claims);
        assertThat(payload.getRkey()).isEqualTo("rkey-123");
    }

    @Test
    @DisplayName("should return default role when rkey is not set")
    void shouldReturnDefaultRoleWhenRkeyNotSet() {
        JwtPayload payload = new JwtPayload();
        assertThat(payload.getRkey()).isEqualTo(JwtClaims.DEFAULT_ROLE);
    }

    @Test
    @DisplayName("should set and get rcode")
    void shouldSetAndGetRcode() {
        JwtPayload payload = new JwtPayload();
        payload.setRcode("admin");
        assertThat(payload.getRcode()).isEqualTo("admin");
    }

    @Test
    @DisplayName("should get bound from claims when present")
    void shouldGetBoundFromClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.BOUND, true);
        payload.setClaims(claims);
        assertThat(payload.isBound()).isTrue();
    }

    @Test
    @DisplayName("should default bound to false")
    void shouldDefaultBoundToFalse() {
        JwtPayload payload = new JwtPayload();
        assertThat(payload.isBound()).isFalse();
    }

    @Test
    @DisplayName("should get initial from claims when present")
    void shouldGetInitialFromClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.INITIAL, true);
        payload.setClaims(claims);
        assertThat(payload.isInitial()).isTrue();
    }

    @Test
    @DisplayName("should default initial to false")
    void shouldDefaultInitialToFalse() {
        JwtPayload payload = new JwtPayload();
        assertThat(payload.isInitial()).isFalse();
    }

    @Test
    @DisplayName("should return empty roles when claims has no roles")
    void shouldReturnEmptyRolesWhenNoRoles() {
        JwtPayload payload = new JwtPayload();
        assertThat(payload.getRoles()).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("should parse roles from string in claims")
    void shouldParseRolesFromStringInClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.ROLES, "[{\"id\":\"1\",\"key\":\"admin\",\"value\":\"Administrator\"}]");
        payload.setClaims(claims);
        List<JwtPayload.RolePair> roles = payload.getRoles();
        assertThat(roles).hasSize(1);
        assertThat(roles.get(0).getKey()).isEqualTo("admin");
    }

    @Test
    @DisplayName("should return empty perms when claims has no perms")
    void shouldReturnEmptyPermsWhenNoPerms() {
        JwtPayload payload = new JwtPayload();
        assertThat(payload.getPerms()).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("should parse perms from string in claims")
    void shouldParsePermsFromStringInClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.PERMS, "user:read,user:write");
        payload.setClaims(claims);
        Set<String> perms = payload.getPerms();
        assertThat(perms).contains("user:read", "user:write");
    }

    @Test
    @DisplayName("should return empty profile when claims has no profile")
    void shouldReturnEmptyProfileWhenNoProfile() {
        JwtPayload payload = new JwtPayload();
        assertThat(payload.getProfile()).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("should parse profile from string in claims")
    void shouldParseProfileFromStringInClaims() {
        JwtPayload payload = new JwtPayload();
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.PROFILE, "{\"email\":\"test@example.com\"}");
        payload.setClaims(claims);
        Map<String, Object> profile = payload.getProfile();
        assertThat(profile).containsEntry("email", "test@example.com");
    }

    @Test
    @DisplayName("should default Spring Security compatibility flags to true")
    void shouldDefaultSecurityFlagsToTrue() {
        JwtPayload payload = new JwtPayload();
        assertThat(payload.isAccountNonExpired()).isTrue();
        assertThat(payload.isAccountNonLocked()).isTrue();
        assertThat(payload.isCredentialsNonExpired()).isTrue();
        assertThat(payload.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("should set and get Spring Security compatibility flags")
    void shouldSetAndGetSecurityFlags() {
        JwtPayload payload = new JwtPayload();
        payload.setAccountNonExpired(false);
        payload.setAccountNonLocked(false);
        payload.setCredentialsNonExpired(false);
        payload.setEnabled(false);
        assertThat(payload.isAccountNonExpired()).isFalse();
        assertThat(payload.isAccountNonLocked()).isFalse();
        assertThat(payload.isCredentialsNonExpired()).isFalse();
        assertThat(payload.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("RolePair should set and get all fields")
    void rolePairShouldSetAndGetAllFields() {
        JwtPayload.RolePair rolePair = new JwtPayload.RolePair("1", "admin", "Administrator");
        assertThat(rolePair.getId()).isEqualTo("1");
        assertThat(rolePair.getKey()).isEqualTo("admin");
        assertThat(rolePair.getValue()).isEqualTo("Administrator");
    }

    @Test
    @DisplayName("RolePair default constructor should create empty object")
    void rolePairDefaultConstructorShouldCreateEmptyObject() {
        JwtPayload.RolePair rolePair = new JwtPayload.RolePair();
        assertThat(rolePair.getId()).isNull();
        assertThat(rolePair.getKey()).isNull();
        assertThat(rolePair.getValue()).isNull();
    }

    @Test
    @DisplayName("RolePair setters should work correctly")
    void rolePairSettersShouldWork() {
        JwtPayload.RolePair rolePair = new JwtPayload.RolePair();
        rolePair.setId("2");
        rolePair.setKey("user");
        rolePair.setValue("User");
        assertThat(rolePair.getId()).isEqualTo("2");
        assertThat(rolePair.getKey()).isEqualTo("user");
        assertThat(rolePair.getValue()).isEqualTo("User");
    }
}
