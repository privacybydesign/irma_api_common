package org.irmacard.api.common.issuing;

import org.irmacard.api.common.ClientRequest;

public class IdentityProviderRequest extends ClientRequest<IssuingRequest> {
	public final static String JWT_SUBJECT = "issue_request";
	public final static String JWT_REQUEST_KEY = "iprequest";

	public IdentityProviderRequest(String data, IssuingRequest request, int timeout) {
		super(data, request, timeout);
	}
}
