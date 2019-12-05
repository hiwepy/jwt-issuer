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

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
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
	private boolean accountNonExpired = true;
	private boolean accountNonLocked = true;
	private boolean credentialsNonExpired = true;
	private boolean enabled = true;
	
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

	public boolean isRestricted() {
		return Boolean.parseBoolean(String.valueOf(getClaims().get("restricted")));
	}
	
	public boolean isInitial() {
		return Boolean.parseBoolean(String.valueOf(claims.get("initial")));
	}
	
	public boolean isFace() {
		return Boolean.parseBoolean(String.valueOf(claims.get("face")));
	}
	
	public String getFaceid() {
		return String.valueOf(getClaims().get("faceid"));
	}
	
	public String getAlias() {
		return StringUtils.isEmpty(alias) ? String.valueOf(getClaims().get("alias")) : alias;
	}

	public String getRoleid() {
		return String.valueOf(getClaims().get("roleid"));
	}
	
	public String getRole() {
		return String.valueOf(getClaims().get("role"));
	}
	
	public Set<SimpleEntry<String, String>> getRoles() {
		Object obj = getClaims().get("roles");
		if(obj != null) {
			Set<SimpleEntry<String, String>> sets = new HashSet<>();
			JSONArray array = JSONObject.parseArray(String.valueOf(obj));
			if(null != array ) {
				for (int index = 0; index < array.size(); index++) {
					JSONObject object = array.getJSONObject(index);
					sets.add(new SimpleEntry<String, String>(object.getString("key"), object.getString("value")));
				}
			}
			return sets;
		}
		return new HashSet<>();
	}

	public List<String> getPerms() {
		Object obj = getClaims().get("perms");
		if(obj != null) {
			return Arrays.asList(StringUtils.tokenizeToStringArray(String.valueOf(obj)));
		}
		return new ArrayList<String>();
	}
	
	@SuppressWarnings("unchecked")
	public Map<String,Object> getProfile() {
		Object obj = getClaims().get("profile");
		if(obj != null) {
			try {
				return JSONObject.parseObject(String.valueOf(obj), Map.class);
			} catch (Exception e) {
			}
		}
		return new HashMap<String,Object>();
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
