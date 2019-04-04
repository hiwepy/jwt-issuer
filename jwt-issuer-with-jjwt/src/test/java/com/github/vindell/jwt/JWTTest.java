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
/**
 * 
 */
package com.github.vindell.jwt;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import com.github.vindell.jwt.utils.JJwtUtils;
import com.github.vindell.jwt.utils.SecretKeyUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * TODO
 * 
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class JWTTest {


	@Test
	public void applyToken1() throws Exception {

		System.out.println("//-----------------------------------------------------------");
		
		// Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
		SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
		
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put("roles", "admin,stu");
		claims.put("perms", "user:del");

		
		String token1 = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(), "Jwt测试1", "test1", "0001", claims, 1024)
				// 压缩，可选GZIP
				.compressWith(CompressionCodecs.DEFLATE)
				// 设置算法（必须）
				.signWith(secretKey).compact();
		System.out.println("token:" + token1);

		Claims claims1 = JJwtUtils.parseJWT(secretKey, token1);
		System.out.println("Audience:" + claims1.getAudience());
		System.out.println("Id:" + claims1.getId());
		System.out.println("Issuer:" + claims1.getIssuer());
		System.out.println("Subject:" + claims1.getSubject());
		System.out.println("Expiration:" + claims1.getExpiration());
		System.out.println("IssuedAt:" + claims1.getIssuedAt());
		System.out.println("NotBefore:" + claims1.getNotBefore());
		System.out.println("roles:" + claims1.get("roles", String.class));
		System.out.println("perms:" + claims1.get("perms", String.class));

		JwtPayload jwtPlayload = JJwtUtils.payload(claims1);
		
		System.out.println("TokenId:" + jwtPlayload.getTokenId());
		System.out.println("Audience:" + jwtPlayload.getAudience());
		System.out.println("Issuer:" + jwtPlayload.getIssuer());
		System.out.println("ClientId:" + jwtPlayload.getClientId());
		System.out.println("Expiration:" + jwtPlayload.getExpiration());
		System.out.println("IssuedAt:" + jwtPlayload.getIssuedAt());
		System.out.println("NotBefore:" + jwtPlayload.getNotBefore());
		System.out.println("roles:" + jwtPlayload.getRoles());
		System.out.println("perms:" + jwtPlayload.getPerms());

		System.out.println("isTokenExpired:" + JJwtUtils.isTokenExpired(secretKey, token1));
	}

	private byte[] base64Secret = Base64.getDecoder().decode("6Tb9jCzN1jXppMrsLYfXbERiGiGp4nNtXuVdTGV9qN0=");
	
	
	@Test
	public void applyToken2() throws Exception {

		
		System.out.println("//-----------------------------------------------------------");
		
		// Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
		SecretKey secretKey = SecretKeyUtils.genSecretKey(base64Secret, "HmacSHA256");
		System.out.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
		
		String token2 = JJwtUtils
				.jwtBuilder(UUID.randomUUID().toString(), "Jwt测试2", "test2", "0002", "admin,stu", "user:del", 1024)
				// 压缩，可选GZIP
				.compressWith(CompressionCodecs.DEFLATE)
				// 设置算法（必须）
				.signWith(secretKey).compact();
		System.out.println("token:" + token2);

		Claims claims2 = JJwtUtils.parseJWT(secretKey, token2);
		System.out.println("Audience:" + claims2.getAudience());
		System.out.println("Id:" + claims2.getId());
		System.out.println("Issuer:" + claims2.getIssuer());
		System.out.println("Subject:" + claims2.getSubject());
		System.out.println("Expiration:" + claims2.getExpiration());
		System.out.println("IssuedAt:" + claims2.getIssuedAt());
		System.out.println("NotBefore:" + claims2.getNotBefore());
		System.out.println("roles:" + claims2.get("roles", String.class));
		System.out.println("perms:" + claims2.get("perms", String.class));

		JwtPayload jwtPlayload2 = JJwtUtils.payload(claims2);
		System.out.println("TokenId:" + jwtPlayload2.getTokenId());
		System.out.println("Audience:" + jwtPlayload2.getAudience());
		System.out.println("Issuer:" + jwtPlayload2.getIssuer());
		System.out.println("ClientId:" + jwtPlayload2.getClientId());
		System.out.println("Expiration:" + jwtPlayload2.getExpiration());
		System.out.println("IssuedAt:" + jwtPlayload2.getIssuedAt());
		System.out.println("NotBefore:" + jwtPlayload2.getNotBefore());
		System.out.println("roles:" + jwtPlayload2.getRoles());
		System.out.println("perms:" + jwtPlayload2.getPerms());

		System.out.println("isTokenExpired:" + JJwtUtils.isTokenExpired(secretKey, token2));

	}
}
