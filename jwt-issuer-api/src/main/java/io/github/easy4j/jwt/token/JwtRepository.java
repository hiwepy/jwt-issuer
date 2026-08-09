package io.github.easy4j.jwt.token;

import java.util.Map;

import io.github.easy4j.jwt.JwtPayload;
import io.github.easy4j.jwt.exception.JwtException;

/**
 * Repository interface for basic JWT operations using a single signing key.
 * Provides methods to issue, verify, and parse JWTs.
 *
 * @param <S> the signing key type
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public interface JwtRepository<S>{

	/**
	 * Issue a JWT with roles and permissions as separate string parameters.
	 *
	 * @param signingKey  the signing key used to sign the JWT
	 * @param jwtId       the unique identifier for the JWT
	 * @param subject     the subject (typically the user identifier)
	 * @param issuer      the issuer of the JWT
	 * @param audience    the intended audience of the JWT
	 * @param roles       comma-separated list of roles
	 * @param permissions comma-separated list of permissions
	 * @param algorithm   the signing algorithm (e.g., HS256, HS384, HS512)
	 * @param period      the expiration period in milliseconds
	 * @return the serialized JWT string
	 * @throws JwtException if JWT issuance fails
	 */
	public abstract String issueJwt(S signingKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period) throws JwtException;

	/**
	 * Issue a JWT with a custom claims map.
	 *
	 * @param signingKey  the signing key used to sign the JWT
	 * @param jwtId       the unique identifier for the JWT
	 * @param subject     the subject (typically the user identifier)
	 * @param issuer      the issuer of the JWT
	 * @param audience    the intended audience of the JWT
	 * @param claims      custom claims to include in the JWT payload
	 * @param algorithm   the signing algorithm (e.g., HS256, HS384, HS512)
	 * @param period      the expiration period in milliseconds
	 * @return the serialized JWT string
	 * @throws JwtException if JWT issuance fails
	 */
	public abstract String issueJwt(S signingKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws JwtException;

	/**
	 * Verify the validity of a JWT token.
	 *
	 * @param signingKey  the signing key used to verify the JWT signature
	 * @param token       the JWT token string to verify
	 * @param checkExpiry whether to check the token's expiration
	 * @return true if the token is valid
	 * @throws JwtException if verification fails
	 */
	public abstract boolean verify(S signingKey, String token, boolean checkExpiry) throws JwtException;

	/**
	 * Parse and extract the payload from a JWT token.
	 *
	 * @param signingKey  the signing key used to verify the JWT signature
	 * @param token       the JWT token string to parse
	 * @param checkExpiry whether to check the token's expiration
	 * @return the parsed JWT payload
	 * @throws JwtException if parsing fails
	 */
	public abstract JwtPayload getPlayload(S signingKey, String token, boolean checkExpiry) throws JwtException;

}
