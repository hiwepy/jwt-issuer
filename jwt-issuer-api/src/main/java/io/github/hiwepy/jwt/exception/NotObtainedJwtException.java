package io.github.easy4j.jwt.exception;

/**
 * Exception thrown when a JWT token is used before its "not before" (nbf) time.
 * This indicates the token is being used prematurely.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@SuppressWarnings("serial")
public class NotObtainedJwtException extends JwtException {

	/**
	 * Constructs a new NotObtainedJwtException with no message or cause.
	 */
	public NotObtainedJwtException() {
		super();
	}

	/**
	 * Constructs a new NotObtainedJwtException with the specified message and cause.
	 *
	 * @param message the detail message
	 * @param cause   the underlying cause
	 */
	public NotObtainedJwtException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs a new NotObtainedJwtException with the specified message.
	 *
	 * @param message the detail message
	 */
	public NotObtainedJwtException(String message) {
		super(message);
	}

	/**
	 * Constructs a new NotObtainedJwtException with the specified cause.
	 *
	 * @param cause the underlying cause
	 */
	public NotObtainedJwtException(Throwable cause) {
		super(cause);
	}

}
