package org.irmacard.api.common.signatures;

import org.irmacard.api.common.ClientRequest;

public class SignatureClientRequest extends ClientRequest<SignatureProofRequest> {
	public final static String JWT_SUBJECT = "signature_request";
	public final static String JWT_REQUEST_KEY = "absrequest";

	private int validity = 0;

	public SignatureClientRequest(String data, SignatureProofRequest request, int validity) {
		super(data, request);
		this.validity = validity;
	}

	public int getValidity() {
		return validity;
	}

	public void setValidity(int validity) {
		this.validity = validity;
	}
}
