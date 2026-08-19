package io.github.easy4j.jwt.exception;

/**
 * Exception thrown when a JWT token is invalid due to claim validation failures,
 * premature token usage, or type mismatches in claims.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@SuppressWarnings("serial")
public class InvalidJwtToken extends JwtException {

	/**
	 * Constructs a new InvalidJwtToken with no message or cause.
	 */
	public InvalidJwtToken() {
		super();
	}

	/**
	 * Constructs a new InvalidJwtToken with the specified message and cause.
	 *
	 * @param message the detail message
	 * @param cause   the underlying cause
	 */
	public InvalidJwtToken(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs a new InvalidJwtToken with the specified message.
	 *
	 * @param message the detail message
	 */
	public InvalidJwtToken(String message) {
		super(message);
	}

	/**
	 * Constructs a new InvalidJwtToken with the specified cause.
	 *
	 * @param cause the underlying cause
	 */
	public InvalidJwtToken(Throwable cause) {
		super(cause);
	}

}
