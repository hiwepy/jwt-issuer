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
import java.util.*;

import javax.crypto.SecretKey;

import com.github.hiwepy.jwt.JwtPayload;
import com.github.hiwepy.jwt.exception.IncorrectJwtException;
import com.github.hiwepy.jwt.exception.InvalidJwtToken;
import com.github.hiwepy.jwt.exception.JwtException;
import com.github.hiwepy.jwt.time.JwtTimeProvider;
import com.github.hiwepy.jwt.utils.NimbusdsUtils;
import com.github.hiwepy.jwt.verifier.ExtendedMACVerifier;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * <b> JSON Web Token (JWT) with HMAC signature and RSA encryption </b>
 * <p> https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-hmac  </p>
 * <p> https://www.connect2id.com/products/nimbus-jose-jwt/examples/jwe-with-shared-key  </p>
 * <p> https://www.connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt </p>
 */
public class SignedWithHamcAndEncryptedWithAESJWTRepository implements JwtKeyPairRepository<String, SecretKey> {

	private JwtTimeProvider timeProvider = JwtTimeProvider.DEFAULT_TIME_PROVIDER;

	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/hiwepy">hiwepy</a>
	 * @param signingKey	: Signing key
	 * @param secretKey		: Encryption key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param roles			: The Roles
	 * @param permissions	: The Perms
	 * @param algorithm		: Supported algorithms：
	 * <p> HS256 - HMAC with SHA-256, requires 256+ bit secret </p>
	 * <p> HS384 - HMAC with SHA-384, requires 384+ bit secret </p>
	 * <p> HS512 - HMAC with SHA-512, requires 512+ bit secret </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public String issueJwt(String signingKey, SecretKey secretKey, String jwtId, String subject, String issuer, Set<String> audience,
			String roles, String permissions, String algorithm, long period)  throws JwtException {

		Map<String, Object> claims =  new HashMap<String, Object>();
		claims.put("roles", roles);
		claims.put("perms", permissions);

		return this.issueJwt(signingKey, secretKey, jwtId, subject, issuer, audience, claims, algorithm, period);

	}

	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/hiwepy">hiwepy</a>
	 * @param signingKey	: Signing key
	 * @param secretKey		: Encryption key
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param claims		: Jwt Claims
	 * @param algorithm		: Supported algorithms：
	 * <p> HS256 - HMAC with SHA-256, requires 256+ bit secret </p>
	 * <p> HS384 - HMAC with SHA-384, requires 384+ bit secret </p>
	 * <p> HS512 - HMAC with SHA-512, requires 512+ bit secret </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public String issueJwt(String signingKey, SecretKey secretKey, String jwtId, String subject, String issuer, Set<String> audience,
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

			//-------------------- Step 2：Hamc Signature --------------------

			// Request JWS Header with HMAC JWSAlgorithm
			JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.parse(algorithm));
			SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);

			// Create HMAC signer
			byte[] secret = Base64.getDecoder().decode(signingKey);
			JWSSigner signer = new MACSigner(secret);

			// Compute the HMAC signature
			signedJWT.sign(signer);

			//-------------------- Step 3：RSA Encrypt ----------------------

			// Request JWT encrypted with DIR and 128-bit AES/GCM
			JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

			// Create JWE object with signed JWT as payload
			JWEObject jweObject = new JWEObject( jweHeader, new Payload(signedJWT));

			// Create an encrypter with the specified public AES key
			JWEEncrypter encrypter = new DirectEncrypter(secretKey);

			// Do the actual encryption
			jweObject.encrypt(encrypter);

			// Serialise to JWE compact form
			return jweObject.serialize();
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
	 * @author 				: <a href="https://github.com/hiwepy">hiwepy</a>
	 * @param signingKey 	:
	 * <p>If the jws was signed with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was signed with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p>
	 * @param secretKey 	:
	 * <p>If the jws was encrypted with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was encrypted with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p>
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return If Validity
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public boolean verify(String signingKey, SecretKey secretKey, String token, boolean checkExpiry) throws JwtException {

		try {

			//-------------------- Step 1：AES Decrypt ----------------------

			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);

			// Decrypt with AES key
			jweObject.decrypt(new DirectDecrypter(secretKey));

			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

			//-------------------- Step 2：Hamc Verify --------------------

			// Create HMAC verifier
			byte[] secret = Base64.getDecoder().decode(signingKey);
			JWSVerifier verifier = checkExpiry ? new ExtendedMACVerifier(secret, signedJWT.getJWTClaimsSet(), this.getTimeProvider()) : new MACVerifier(secret) ;

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
	 * @param secretKey 	:
	 * <p>If the jws was encrypted with a SecretKey, the same SecretKey should be specified on the JwtParser. </p>
	 * <p>If the jws was encrypted with a PrivateKey, that key's corresponding PublicKey (not the PrivateKey) should be specified on the JwtParser.</p>
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return JwtPlayload {@link JwtPayload}
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public JwtPayload getPlayload(String signingKey, SecretKey secretKey, String token, boolean checkExpiry)  throws JwtException {
		try {

			//-------------------- Step 1：AES Decrypt ----------------------

			// Parse the JWE string
			JWEObject jweObject = JWEObject.parse(token);

			// Decrypt with AES key
			jweObject.decrypt(new DirectDecrypter(secretKey));

			// Extract payload
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

			//-------------------- Step 2：Hamc Verify --------------------

			// Create HMAC verifier
			byte[] secret = Base64.getDecoder().decode(signingKey);
			JWSVerifier verifier = checkExpiry ? new ExtendedMACVerifier(secret, signedJWT.getJWTClaimsSet(), this.getTimeProvider()) : new MACVerifier(secret) ;

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
