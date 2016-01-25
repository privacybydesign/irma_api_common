package org.irmacard.api.common;

public class IdentityProviderRequest extends ClientRequest<IssuingRequest> {
	public IdentityProviderRequest(String data, IssuingRequest request, int timeout) {
		super(data, request, timeout);
	}
}
