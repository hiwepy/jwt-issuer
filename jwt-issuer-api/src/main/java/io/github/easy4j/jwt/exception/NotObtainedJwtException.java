package io.github.easy4j.jwt.exception;

@SuppressWarnings("serial")
/**
 * Exception class for JWT processing errors.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class NotObtainedJwtException extends JwtException {
	
	public NotObtainedJwtException() {
		super();
	}

	public NotObtainedJwtException(String message, Throwable cause) {
		super(message, cause);
	}

	public NotObtainedJwtException(String message) {
		super(message);
	}

	public NotObtainedJwtException(Throwable cause) {
		super(cause);
	}
	
}
