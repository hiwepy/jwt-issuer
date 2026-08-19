package io.github.easy4j.jwt.exception;

@SuppressWarnings("serial")
/**
 * Exception class for JWT processing errors.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class IncorrectJwtException extends JwtException {
	
	public IncorrectJwtException() {
		super();
	}

	public IncorrectJwtException(String message, Throwable cause) {
		super(message, cause);
	}

	public IncorrectJwtException(String message) {
		super(message);
	}

	public IncorrectJwtException(Throwable cause) {
		super(cause);
	}
	
}
