package com.github.vindell.jwt.token;

import java.util.Map;

import com.github.vindell.jwt.JwtPayload;
import com.github.vindell.jwt.exception.JwtException;

public interface JwtKeyResolverRepository<S>{
	
	public abstract String issueJwt(S signingKey, String keyId, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period) throws JwtException;

	public abstract String issueJwt(S signingKey, String keyId, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws JwtException;
	
	public abstract boolean verify(String token, boolean checkExpiry) throws JwtException;
	
	public abstract JwtPayload getPlayload(String token, boolean checkExpiry) throws JwtException;
	
}
