package org.irmacard.api.common.exceptions;

/**
 * Errors that can occur in usage of the API, along with their HTTP status code
 * and human-readable descriptions. For use in {@link ApiError} and {@link ApiException}.
 */
@SuppressWarnings("unused")
public enum ApiError {
	// IdP-specific errors
	MALFORMED_ISSUER_REQUEST(400, "Malformed issuer request"),
	INVALID_TIMESTAMP(400, "Timestamp was not an epoch boundary"),
	ISSUING_DISABLED(403, "This server does not support issuing"),

	// SP-specific errors
	MALFORMED_VERIFIER_REQUEST(400, "Malformed verification request"),

	// Token errors
	INVALID_PROOFS(400, "Invalid secret key commitments and/or disclosure proofs"),
	ATTRIBUTES_MISSING(400, "Not all requested-for attributes were present"),
	ATTRIBUTES_EXPIRED(400, "Disclosed attributes were expired"),
	UNEXPECTED_REQUEST(403, "Unexpected request in this state"),

	// IdP or SP errors
	JWT_INVALID(401, "JSON web token did not verify"),
	JWT_TOO_OLD(401, "JSON web token was too old"),
	UNAUTHORIZED(403, "You are not authorized to issue or verify this attribute"),
	ATTRIBUTES_WRONG(400, "Specified attribute(s) do not belong to this credential type"),

	// SP, IdP, or token errors
	SESSION_UNKNOWN(400, "Unknown or expired session"),
	SESSION_TOKEN_MALFORMED(400, "Malformed session token"),
	MALFORMED_INPUT(400, "Input could not be parsed"),

	// Our errors
	CANNOT_ISSUE(500, "Cannot issue this credential"),
	ISSUANCE_FAILED(500, "Failed to create credential(s)"),

	// Any other exception
	EXCEPTION(500, "Encountered unexpected problem");


	private int statusCode;
	private String description;

	ApiError(int statusCode, String description) {
		this.statusCode = statusCode;
		this.description = description;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public String getDescription() {
		return description;
	}
}
