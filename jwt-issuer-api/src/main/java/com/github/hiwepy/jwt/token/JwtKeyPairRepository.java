package com.github.hiwepy.jwt.token;

import java.util.Map;

import com.github.hiwepy.jwt.exception.JwtException;
import com.github.hiwepy.jwt.JwtPayload;

/**
 * JWT令牌存储库
 * @param <S>
 * @param <E>
 */
public interface JwtKeyPairRepository<S, E> {

	/**
	 * 生成JWT令牌
	 * @param signingKey 签名密钥
	 * @param secretKey 加密密钥
	 * @param jwtId 令牌ID
	 * @param subject 主题
	 * @param issuer 签发者
	 * @param audience 接收者
	 * @param roles 角色
	 * @param permissions 权限
	 * @param algorithm 算法
	 * @param period 有效期
	 * @return JWT令牌
	 * @throws JwtException Jwt异常
	 */
	String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period) throws JwtException;

	/**
	 * 生成JWT令牌
	 * @param signingKey 签名密钥
	 * @param secretKey 加密密钥
	 * @param jwtId 令牌ID
	 * @param subject 主题
	 * @param issuer 签发者
	 * @param audience 接收者
	 * @param claims 声明
	 * @param algorithm 算法
	 * @param period 有效期
	 * @return JWT令牌
	 * @throws JwtException Jwt异常
	 */
	String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws JwtException;

	/**
	 * 验证JWT令牌
	 * @param signingKey 签名密钥
	 * @param secretKey 加密密钥
	 * @param token 令牌
	 * @param checkExpiry 是否检查过期
	 * @return 是否验证通过
	 * @throws JwtException Jwt异常
	 */
	boolean verify(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws JwtException;

	/**
	 * 获取JWT内容
	 * @param signingKey 签名密钥
	 * @param secretKey 加密密钥
	 * @param token 令牌
	 * @param checkExpiry 是否检查过期
	 * @return JWT内容
	 * @throws JwtException Jwt异常
	 */
	JwtPayload getPlayload(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws JwtException;
}
