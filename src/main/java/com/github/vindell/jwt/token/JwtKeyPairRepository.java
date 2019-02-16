package com.github.vindell.jwt.token;

import java.util.Map;

import com.github.vindell.jwt.exception.AuthenticationException;
import com.github.vindell.jwt.JwtPayload;

public interface JwtKeyPairRepository<S, E> {

	public abstract String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period) throws AuthenticationException;
	
	public abstract String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws AuthenticationException;

	public abstract boolean verify(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws AuthenticationException;

	public abstract JwtPayload getPlayload(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws AuthenticationException;
}
