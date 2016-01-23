package org.irmacard.api.common.exceptions;

/**
 * Exception occuring during usage of the API. Mainly a wrapper around an {@link ApiError}.
 */
public class ApiException extends RuntimeException {
	private static final long serialVersionUID = 5763289075477918475L;

	private ApiError error;

	public ApiException(ApiError error) {
		this.error = error;
	}

	public ApiException(ApiError error, String message) {
		super(message);
		this.error = error;
	}

	public ApiError getError() {
		return error;
	}
}
