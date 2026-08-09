package io.github.easy4j.jwt.token;

import java.util.Map;

import io.github.easy4j.jwt.exception.JwtException;
import io.github.easy4j.jwt.JwtPayload;

/**
 * Repository interface for JWT operations that require a key pair.
 *
 * @param <S> the signing key type
 * @param <E> the encryption key type
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public interface JwtKeyPairRepository<S, E> {

	public abstract String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period) throws JwtException;
	
	public abstract String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws JwtException;

	public abstract boolean verify(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws JwtException;

	public abstract JwtPayload getPlayload(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws JwtException;
}
