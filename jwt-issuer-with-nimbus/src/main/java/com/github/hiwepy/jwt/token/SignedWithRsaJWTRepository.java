/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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
package com.github.hiwepy.jwt.token;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.github.hiwepy.jwt.JwtPayload;
import com.github.hiwepy.jwt.exception.IncorrectJwtException;
import com.github.hiwepy.jwt.exception.InvalidJwtToken;
import com.github.hiwepy.jwt.exception.JwtException;
import com.github.hiwepy.jwt.time.JwtTimeProvider;
import com.github.hiwepy.jwt.utils.NimbusdsUtils;
import com.github.hiwepy.jwt.verifier.ExtendedRSASSAVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * <b> JSON Web Token (JWT) with RSA signature </b>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-signature 
 */
public class SignedWithRsaJWTRepository implements JwtRepository<RSAKey> {

	private JwtTimeProvider timeProvider = JwtTimeProvider.DEFAULT_TIME_PROVIDER;
	
	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/hiwepy">hiwepy</a>
	 * @param signingKey	: Signing key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param roles			: The Roles
	 * @param permissions	: The Perms
	 * @param algorithm		: Supported algorithms：
	 * <p> RS256 - RSA PKCS#1 signature with SHA-256 </p>
	 * <p> RS384 - RSA PKCS#1 signature with SHA-384 </p>
	 * <p> RS512 - RSA PKCS#1 signature with SHA-512 </p>
	 * <p> PS256 - RSA PSS signature with SHA-256 </p>
	 * <p> PS384 - RSA PSS signature with SHA-384 </p>
	 * <p> PS512 - RSA PSS signature with SHA-512 </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public String issueJwt(RSAKey signingKey, String jwtId, String subject, String issuer, Set<String> audience,
			String roles, String permissions, String algorithm, long period)  throws JwtException {
		
		Map<String, Object> claims =  new HashMap<String, Object>();
		claims.put("roles", roles);
		claims.put("perms", permissions);
		
		return this.issueJwt(signingKey, jwtId, subject, issuer, audience, claims, algorithm, period);
		
	}
	
	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/hiwepy">hiwepy</a>
	 * @param signingKey	: Signing key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param claims		: Jwt Claims
	 * @param algorithm		: Supported algorithms：
	 * <p> RS256 - RSA PKCS#1 signature with SHA-256 </p>
	 * <p> RS384 - RSA PKCS#1 signature with SHA-384 </p>
	 * <p> RS512 - RSA PKCS#1 signature with SHA-512 </p>
	 * <p> PS256 - RSA PSS signature with SHA-256 </p>
	 * <p> PS384 - RSA PSS signature with SHA-384 </p>
	 * <p> PS512 - RSA PSS signature with SHA-512 </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public String issueJwt(RSAKey signingKey, String jwtId, String subject, String issuer,  Set<String> audience,
			Map<String, Object> claims,	String algorithm, long period) throws JwtException {
		try {
			
			//-------------------- Step 1：Get ClaimsSet --------------------
			
			// Prepare JWT with claims set
			JWTClaimsSet.Builder builder = NimbusdsUtils.claimsSet(jwtId, subject, issuer, audience, claims, period);
			// 签发时间
			long currentTimeMillis = this.getTimeProvider().now();
			Date now = new Date(currentTimeMillis);
			builder.issueTime(now);
			// 有效期起始时间
			builder.notBeforeTime(now);
			// Token过期时间
			if (period >= 0) {
				// 有效时间
				Date expiration = new Date(currentTimeMillis + period );
				builder.expirationTime(expiration);
			}
			JWTClaimsSet claimsSet = builder.build();
			
			//-------------------- Step 2：RSA Signature --------------------
			
			// Create RSA-signer with the private key
			JWSSigner signer = new RSASSASigner(signingKey);
			
			// Request JWS Header with JWSAlgorithm
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm)).build();
			SignedJWT signedJWT = new SignedJWT(header, claimsSet);
			
			// Compute the RSA signature
			signedJWT.sign(signer);
			
			// To serialize to compact form, produces something like
			// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
			// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
			// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
			// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
			return signedJWT.serialize();
		} catch (KeyLengthException e) {
			throw new IncorrectJwtException(e);
		} catch (JOSEException e) {
			throw new IncorrectJwtException(e);
		}
	}


	/**
	 * Verify the validity of JWT
	 * @author 				: <a href="https://github.com/hiwepy">hiwepy</a>
	 * @param signingKey 	: 
	 * <p>If the jws was signed with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was signed with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p> 
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return If Validity
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public boolean verify(RSAKey signingKey, String token, boolean checkExpiry) throws JwtException {

		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			//-------------------- Step 2：RSA Verify --------------------
			
			// Create RSA verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedRSASSAVerifier(signingKey, signedJWT.getJWTClaimsSet(), this.getTimeProvider()) : new RSASSAVerifier(signingKey) ;
			
			// Retrieve / verify the JWT claims according to the app requirements
			return signedJWT.verify(verifier);
		} catch (IllegalStateException e) {
			throw new IncorrectJwtException(e);
		} catch (NumberFormatException e) {
			throw new IncorrectJwtException(e);
		} catch (ParseException e) {
			throw new IncorrectJwtException(e);
		} catch (JOSEException e) {
			throw new InvalidJwtToken(e);
		}
	}

	/**
	 * Parser JSON Web Token (JWT)
	 * @author 		：<a href="https://github.com/hiwepy">hiwepy</a>
	 * @param signingKey 	: 
	 * <p>If the jws was signed with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was signed with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p> 
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return JwtPlayload {@link JwtPayload}
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public JwtPayload getPlayload(RSAKey signingKey, String token, boolean checkExpiry)  throws JwtException {
		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			
			//-------------------- Step 2：RSA Verify --------------------
			
			// Create RSA verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedRSASSAVerifier(signingKey, signedJWT.getJWTClaimsSet(), this.getTimeProvider()) : new RSASSAVerifier(signingKey) ;
			
			// Retrieve / verify the JWT claims according to the app requirements
			if(!signedJWT.verify(verifier)) {
				throw new JwtException(String.format("Invalid JSON Web Token (JWT) : %s", token));
			}
			
			//-------------------- Step 3：Gets The Claims ---------------
			
			// Retrieve JWT claims
			return NimbusdsUtils.payload(signedJWT.getJWTClaimsSet());
		} catch (IllegalStateException e) {
			throw new IncorrectJwtException(e);
		} catch (NumberFormatException e) {
			throw new IncorrectJwtException(e);
		} catch (ParseException e) {
			throw new IncorrectJwtException(e);
		} catch (JOSEException e) {
			throw new InvalidJwtToken(e);
		}
	}

	public JwtTimeProvider getTimeProvider() {
		return timeProvider;
	}

	public void setTimeProvider(JwtTimeProvider timeProvider) {
		this.timeProvider = timeProvider;
	}
	
}
