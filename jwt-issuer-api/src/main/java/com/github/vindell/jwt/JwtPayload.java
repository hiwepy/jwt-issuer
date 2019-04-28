/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.github.vindell.jwt;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.github.vindell.jwt.utils.StringUtils;

/**
 * TODO
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class JwtPayload {

	private String tokenId;// 令牌id
	private String clientId;// 客户标识（用户名、账号）
	private String alias;// 客户别名
	private String issuer;// 签发者(JWT令牌此项有值)
	private Date issuedAt;// 签发时间
	private Date expiration;// 过期时间
	private Date notBefore;// not-before 时间
	private List<String> audience;// 接收方(JWT令牌此项有值)
	private Map<String, Object> claims;// 访问主张(JWT令牌此项有值)
	private String host;// 客户地址
	
	/**
	 * 兼容 Spring Security
	 */
	private boolean accountNonExpired;
	private boolean accountNonLocked;
	private boolean credentialsNonExpired;
	private boolean enabled;
	
	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public Date getIssuedAt() {
		return issuedAt;
	}

	public void setIssuedAt(Date issuedAt) {
		this.issuedAt = issuedAt;
	}
	
	public Date getExpiration() {
		return expiration;
	}

	public void setExpiration(Date expiration) {
		this.expiration = expiration;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public List<String> getAudience() {
		return audience;
	}

	public void setAudience(List<String> audience) {
		this.audience = audience;
	}

	public Map<String, Object> getClaims() {
		return claims == null ? new HashMap<String, Object>() : claims;
	}

	public void setClaims(Map<String, Object> claims) {
		this.claims = claims;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}
	
	public String getAlias() {
		return StringUtils.isEmpty(alias) ? String.valueOf(getClaims().get("alias")) : alias;
	}

	public String getRoles() {
		return String.valueOf(getClaims().get("roles"));
	}

	public String getPerms() {
		return String.valueOf(getClaims().get("perms"));
	}

	public boolean isAccountNonExpired() {
		return accountNonExpired;
	}

	public void setAccountNonExpired(boolean accountNonExpired) {
		this.accountNonExpired = accountNonExpired;
	}

	public boolean isAccountNonLocked() {
		return accountNonLocked;
	}

	public void setAccountNonLocked(boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}

	public boolean isCredentialsNonExpired() {
		return credentialsNonExpired;
	}

	public void setCredentialsNonExpired(boolean credentialsNonExpired) {
		this.credentialsNonExpired = credentialsNonExpired;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}
	
}
