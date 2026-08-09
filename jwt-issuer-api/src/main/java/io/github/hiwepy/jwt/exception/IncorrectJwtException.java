package io.github.easy4j.jwt.exception;

/**
 * Exception thrown when a JWT token has an incorrect format or structure.
 * This includes malformed tokens, missing claims, or invalid signatures.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@SuppressWarnings("serial")
public class IncorrectJwtException extends JwtException {

	/**
	 * Constructs a new IncorrectJwtException with no message or cause.
	 */
	public IncorrectJwtException() {
		super();
	}

	/**
	 * Constructs a new IncorrectJwtException with the specified message and cause.
	 *
	 * @param message the detail message
	 * @param cause   the underlying cause
	 */
	public IncorrectJwtException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs a new IncorrectJwtException with the specified message.
	 *
	 * @param message the detail message
	 */
	public IncorrectJwtException(String message) {
		super(message);
	}

	/**
	 * Constructs a new IncorrectJwtException with the specified cause.
	 *
	 * @param cause the underlying cause
	 */
	public IncorrectJwtException(Throwable cause) {
		super(cause);
	}

}
