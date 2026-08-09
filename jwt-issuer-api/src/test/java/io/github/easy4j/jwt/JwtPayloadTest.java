package io.github.easy4j.jwt;

import java.util.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtPayload Tests")
class JwtPayloadTest {
    @Test void shouldSetAndGetTokenId() { var p = new JwtPayload(); p.setTokenId("t1"); assertThat(p.getTokenId()).isEqualTo("t1"); }
    @Test void shouldSetAndGetSubject() { var p = new JwtPayload(); p.setSubject("u1"); assertThat(p.getSubject()).isEqualTo("u1"); }
    @Test void shouldSetAndGetClientName() { var p = new JwtPayload(); p.setClientName("Test"); assertThat(p.getClientName()).isEqualTo("Test"); }
    @Test void shouldFallbackClientNameToClaimsUname() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.UNAME, "fb"); p.setClaims(c); assertThat(p.getClientName()).isEqualTo("fb"); }
    @Test void shouldSetAndGetIssuer() { var p = new JwtPayload(); p.setIssuer("i1"); assertThat(p.getIssuer()).isEqualTo("i1"); }
    @Test void shouldSetAndGetIssuedAt() { var p = new JwtPayload(); var d = new Date(); p.setIssuedAt(d); assertThat(p.getIssuedAt()).isEqualTo(d); }
    @Test void shouldSetAndGetExpiration() { var p = new JwtPayload(); var d = new Date(); p.setExpiration(d); assertThat(p.getExpiration()).isEqualTo(d); }
    @Test void shouldSetAndGetNotBefore() { var p = new JwtPayload(); var d = new Date(); p.setNotBefore(d); assertThat(p.getNotBefore()).isEqualTo(d); }
    @Test void shouldSetAndGetAudience() { var p = new JwtPayload(); p.setAudience(Arrays.asList("a1","a2")); assertThat(p.getAudience()).containsExactly("a1","a2"); }
    @Test void shouldReturnEmptyMapWhenClaimsIsNull() { assertThat(new JwtPayload().getClaims()).isNotNull().isEmpty(); }
    @Test void shouldSetAndGetClaims() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put("k","v"); p.setClaims(c); assertThat(p.getClaims()).containsEntry("k","v"); }
    @Test void shouldSetAndGetHost() { var p = new JwtPayload(); p.setHost("1.2.3.4"); assertThat(p.getHost()).isEqualTo("1.2.3.4"); }
    @Test void shouldGetUidFromClaims() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.UID, "u1"); p.setClaims(c); assertThat(p.getUid()).isEqualTo("u1"); }
    @Test void shouldGetUuidFromClaims() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.UUID, "uu1"); p.setClaims(c); assertThat(p.getUuid()).isEqualTo("uu1"); }
    @Test void shouldGetUkeyFromClaims() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.UKEY, "uk1"); p.setClaims(c); assertThat(p.getUkey()).isEqualTo("uk1"); }
    @Test void shouldGetUcodeFromClaims() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.UCODE, "uc1"); p.setClaims(c); assertThat(p.getUcode()).isEqualTo("uc1"); }
    @Test void shouldGetRidFromClaims() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.RID, "r1"); p.setClaims(c); assertThat(p.getRid()).isEqualTo("r1"); }
    @Test void shouldGetRkeyFromClaims() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.RKEY, "rk1"); p.setClaims(c); assertThat(p.getRkey()).isEqualTo("rk1"); }
    @Test void shouldReturnDefaultRoleWhenRkeyNotSet() { assertThat(new JwtPayload().getRkey()).isEqualTo(JwtClaims.DEFAULT_ROLE); }
    @Test void shouldSetAndGetRcode() { var p = new JwtPayload(); p.setRcode("admin"); assertThat(p.getRcode()).isEqualTo("admin"); }
    @Test void shouldGetBoundFromClaims() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.BOUND, true); p.setClaims(c); assertThat(p.isBound()).isTrue(); }
    @Test void shouldDefaultBoundToFalse() { assertThat(new JwtPayload().isBound()).isFalse(); }
    @Test void shouldGetInitialFromClaims() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.INITIAL, true); p.setClaims(c); assertThat(p.isInitial()).isTrue(); }
    @Test void shouldDefaultInitialToFalse() { assertThat(new JwtPayload().isInitial()).isFalse(); }
    @Test void shouldReturnEmptyRolesWhenNoRoles() { assertThat(new JwtPayload().getRoles()).isNotNull().isEmpty(); }
    @Test void shouldParseRolesFromString() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.ROLES, "[{\"id\":\"1\",\"key\":\"admin\",\"value\":\"Admin\"}]"); p.setClaims(c); assertThat(p.getRoles()).hasSize(1); }
    @Test void shouldReturnEmptyPermsWhenNoPerms() { assertThat(new JwtPayload().getPerms()).isNotNull().isEmpty(); }
    @Test void shouldParsePermsFromString() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.PERMS, "r,w"); p.setClaims(c); assertThat(p.getPerms()).contains("r","w"); }
    @Test void shouldReturnEmptyProfileWhenNoProfile() { assertThat(new JwtPayload().getProfile()).isNotNull().isEmpty(); }
    @Test void shouldParseProfileFromString() { var p = new JwtPayload(); Map<String, Object> c = new HashMap<>(); c.put(JwtClaims.PROFILE, "{\"e\":\"t@t.com\"}"); p.setClaims(c); assertThat(p.getProfile()).containsEntry("e","t@t.com"); }
    @Test void shouldDefaultSecurityFlagsToTrue() { var p = new JwtPayload(); assertThat(p.isAccountNonExpired()).isTrue(); assertThat(p.isAccountNonLocked()).isTrue(); assertThat(p.isCredentialsNonExpired()).isTrue(); assertThat(p.isEnabled()).isTrue(); }
    @Test void shouldSetAndGetSecurityFlags() { var p = new JwtPayload(); p.setAccountNonExpired(false); p.setAccountNonLocked(false); p.setCredentialsNonExpired(false); p.setEnabled(false); assertThat(p.isAccountNonExpired()).isFalse(); assertThat(p.isAccountNonLocked()).isFalse(); assertThat(p.isCredentialsNonExpired()).isFalse(); assertThat(p.isEnabled()).isFalse(); }
    @Test void rolePairShouldSetAndGetAllFields() { var rp = new JwtPayload.RolePair("1","admin","Admin"); assertThat(rp.getId()).isEqualTo("1"); assertThat(rp.getKey()).isEqualTo("admin"); assertThat(rp.getValue()).isEqualTo("Admin"); }
    @Test void rolePairDefaultConstructorShouldCreateEmptyObject() { var rp = new JwtPayload.RolePair(); assertThat(rp.getId()).isNull(); assertThat(rp.getKey()).isNull(); assertThat(rp.getValue()).isNull(); }
    @Test void rolePairSettersShouldWork() { var rp = new JwtPayload.RolePair(); rp.setId("2"); rp.setKey("u"); rp.setValue("U"); assertThat(rp.getId()).isEqualTo("2"); assertThat(rp.getKey()).isEqualTo("u"); assertThat(rp.getValue()).isEqualTo("U"); }
}
