package org.irmacard.api.common.exceptions;

/**
 * Errors that can occur in usage of the API, along with their HTTP status code
 * and human-readable descriptions. For use in {@link ApiError} and {@link ApiException}.
 */
@SuppressWarnings("unused")
public enum ApiError {
	// IdP errors
	MALFORMED_ISSUER_REQUEST(400, "Malformed issuer request"),
	ATTRIBUTES_WRONG(400, "Specified attribute(s) do not belong to this credential type"),
	INVALID_TIMESTAMP(400, "Timestamp was not an epoch boundary"),
	JWT_INVALID(401, "JSON web token did not verify"),
	JWT_TOO_OLD(401, "JSON web token was too old"),
	UNAUTHORIZED(403, "You are not authorized to issue this credential"),
	ISSUING_DISABLED(403, "This server does not support issuing"),

	// SP errors
	MALFORMED_VERIFIER_REQUEST(400, "Malformed verification request"),

	// SP, IdP, or token errors
	SESSION_UNKNOWN(400, "Unknown or expired session"),
	SESSION_TOKEN_MALFORMED(400, "Malformed session token"),
	MALFORMED_INPUT(400, "Input could not be parsed"),

	// Token errors
	INVALID_PROOFS(400, "Invalid secret key commitments and/or disclosure proofs"),
	ATTRIBUTES_MISSING(400, "Not all requested-for attributes were present"),
	ATTRIBUTES_EXPIRED(400, "Disclosed attributes were expired"),
	UNEXPECTED_REQUEST(403, "Unexpected request in this state"),

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
