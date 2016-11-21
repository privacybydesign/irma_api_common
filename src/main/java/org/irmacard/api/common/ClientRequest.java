package org.irmacard.api.common;


public class ClientRequest<T> {
	private int timeout = 0;
	private String data;
	private T request;
	private String callbackUrl;

	public ClientRequest() {}

	public ClientRequest(String data, T request) {
		this.request = request;
		this.data = data;
	}

	public ClientRequest(String data, T request, int timeout) {
		this.timeout = timeout;
		this.request = request;
		this.data = data;
	}

	public ClientRequest(String data, T request, int timeout, String callbackUrl) {
		this(data, request, timeout);
		this.callbackUrl = callbackUrl;
	}

	public String getCallbackUrl() {
		return callbackUrl;
	}

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	public T getRequest() {
		return request;
	}

	public String getData() {
		return data;
	}
}
