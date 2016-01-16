package org.irmacard.api.common;

public class IdentityProviderRequest {
	private int timeout = 10;
	private String data;
	private IssuingRequest request;

	public IdentityProviderRequest(String data, IssuingRequest request, int timeout) {
		this.data = data;
		this.request = request;
		this.timeout = timeout;
	}

	public IssuingRequest getRequest() {
		return request;
	}

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	public String getData() {
		return data;
	}
}
