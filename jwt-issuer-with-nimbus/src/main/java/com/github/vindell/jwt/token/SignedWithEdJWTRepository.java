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
package com.github.vindell.jwt.token;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.github.vindell.jwt.JwtPayload;
import com.github.vindell.jwt.exception.IncorrectJwtException;
import com.github.vindell.jwt.exception.InvalidJwtToken;
import com.github.vindell.jwt.exception.JwtException;
import com.github.vindell.jwt.time.JwtTimeProvider;
import com.github.vindell.jwt.utils.NimbusdsUtils;
import com.github.vindell.jwt.verifier.ExtendedEd25519Verifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * <b> JSON Web Token (JWT) with EdDSA signature </b>
 * https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-eddsa
 */
public class SignedWithEdJWTRepository implements JwtRepository<OctetKeyPair> {
	
	private JwtTimeProvider timeProvider = JwtTimeProvider.DEFAULT_TIME_PROVIDER;
	
	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param signingKey	: Signing key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param roles			: The Roles
	 * @param permissions	: The Perms
	 * @param algorithm		: JWS algorithm: Ed25519
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public String issueJwt(OctetKeyPair signingKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period)  throws JwtException {
		
		Map<String, Object> claims =  new HashMap<String, Object>();
		claims.put("roles", roles);
		claims.put("perms", permissions);
		
		return this.issueJwt(signingKey, jwtId, subject, issuer, audience, claims, algorithm, period);
		
	}
	

	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param signingKey	: Signing key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param claims		: Jwt Claims
	 * @param algorithm		: JWS algorithm: Ed25519
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public String issueJwt(OctetKeyPair signingKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws JwtException {
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
			
			//-------------------- Step 2：EdDSA Signature --------------------
			
			// Request JWS Header with EdDSA JWSAlgorithm
			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(signingKey.getKeyID()).build();
			SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
						
			// Create the EdDSA signer
			JWSSigner signer = new Ed25519Signer(signingKey);
			
			// Compute the EC signature
			signedJWT.sign(signer);
			
			// Serialize the JWS to compact form
			return signedJWT.serialize();
		} catch (IllegalStateException e) {
			throw new IncorrectJwtException(e);
		} catch (KeyLengthException e) {
			throw new IncorrectJwtException(e);
		} catch (JOSEException e) {
			throw new IncorrectJwtException(e);
		}
	}

	/**
	 * Verify the validity of JWT
	 * @author 				: <a href="https://github.com/vindell">vindell</a>
	 * @param signingKey 	: 
	 * <p>If the jws was signed with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was signed with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p> 
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return If Validity
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public boolean verify(OctetKeyPair signingKey, String token, boolean checkExpiry) throws JwtException {

		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS and verify its EdDSA signature
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			//-------------------- Step 2：EdDSA Verify --------------------
			
			// Create Ed25519 verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedEd25519Verifier(signingKey.toPublicJWK(), signedJWT.getJWTClaimsSet(), this.getTimeProvider()) : new Ed25519Verifier(signingKey.toPublicJWK());
			
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
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param signingKey 	: 
	 * <p>If the jws was signed with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was signed with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p> 
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return JwtPlayload {@link JwtPayload}
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public JwtPayload getPlayload(OctetKeyPair signingKey, String token, boolean checkExpiry)  throws JwtException {
		try {
			
			//-------------------- Step 1：JWT Parse --------------------
			
			// On the consumer side, parse the JWS and verify its EdDSA signature
			SignedJWT signedJWT = SignedJWT.parse(token);
			
			//-------------------- Step 2：EdDSA Verify --------------------
			
			// Create Ed25519 verifier
			JWSVerifier verifier = checkExpiry ? new ExtendedEd25519Verifier(signingKey.toPublicJWK(), signedJWT.getJWTClaimsSet(), this.getTimeProvider()) : new Ed25519Verifier(signingKey.toPublicJWK());
						
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
