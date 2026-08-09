package io.github.easy4j.jwt.token;

import java.util.Map;

import io.github.easy4j.jwt.exception.JwtException;
import io.github.easy4j.jwt.JwtPayload;

/**
 * Repository interface for JWT operations that require a key pair (signing key and encryption key).
 * Provides methods to issue, verify, and parse JWTs using asymmetric key pairs.
 *
 * @param <S> the signing key type
 * @param <E> the encryption key type
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public interface JwtKeyPairRepository<S, E> {

	/**
	 * Issue a JWT with roles and permissions as separate string parameters.
	 *
	 * @param signingKey  the signing key used to sign the JWT
	 * @param secretKey   the encryption key used to encrypt the JWT
	 * @param jwtId       the unique identifier for the JWT
	 * @param subject     the subject (typically the user identifier)
	 * @param issuer      the issuer of the JWT
	 * @param audience    the intended audience of the JWT
	 * @param roles       comma-separated list of roles
	 * @param permissions comma-separated list of permissions
	 * @param algorithm   the signing algorithm (e.g., ES256, ES384, ES512)
	 * @param period      the expiration period in milliseconds
	 * @return the serialized JWT string
	 * @throws JwtException if JWT issuance fails
	 */
	public abstract String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period) throws JwtException;

	/**
	 * Issue a JWT with a custom claims map.
	 *
	 * @param signingKey  the signing key used to sign the JWT
	 * @param secretKey   the encryption key used to encrypt the JWT
	 * @param jwtId       the unique identifier for the JWT
	 * @param subject     the subject (typically the user identifier)
	 * @param issuer      the issuer of the JWT
	 * @param audience    the intended audience of the JWT
	 * @param claims      custom claims to include in the JWT payload
	 * @param algorithm   the signing algorithm (e.g., ES256, ES384, ES512)
	 * @param period      the expiration period in milliseconds
	 * @return the serialized JWT string
	 * @throws JwtException if JWT issuance fails
	 */
	public abstract String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws JwtException;

	/**
	 * Verify the validity of a JWT token.
	 *
	 * @param signingKey  the signing key used to verify the JWT signature
	 * @param secretKey   the encryption key used to decrypt the JWT
	 * @param token       the JWT token string to verify
	 * @param checkExpiry whether to check the token's expiration
	 * @return true if the token is valid
	 * @throws JwtException if verification fails
	 */
	public abstract boolean verify(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws JwtException;

	/**
	 * Parse and extract the payload from a JWT token.
	 *
	 * @param signingKey  the signing key used to verify the JWT signature
	 * @param secretKey   the encryption key used to decrypt the JWT
	 * @param token       the JWT token string to parse
	 * @param checkExpiry whether to check the token's expiration
	 * @return the parsed JWT payload
	 * @throws JwtException if parsing fails
	 */
	public abstract JwtPayload getPlayload(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws JwtException;
}
