package org.irmacard.api.common;

import org.irmacard.credentials.info.CredentialDescription;

import java.math.BigInteger;
import java.util.ArrayList;

public class IssuingRequest {
	private ArrayList<CredentialRequest> credentials;
	private BigInteger nonce;
	private BigInteger context;

	public IssuingRequest(BigInteger nonce, BigInteger context, ArrayList<CredentialRequest> credentials) {
		this.credentials = credentials;
		this.nonce = nonce;
		this.context = context;
	}

	public BigInteger getNonce() {
		return nonce;
	}

	public void setNonce(BigInteger nonce) {
		this.nonce = nonce;
	}

	public BigInteger getContext() {
		return context;
	}

	public void setContext(BigInteger context) {
		this.context = context;
	}

	public ArrayList<CredentialRequest> getCredentials() {
		return credentials;
	}

	/**
	 * Checks if the amount and names of the attributes of all containing credentials match those from the
	 * description store.
	 */
	public boolean credentialsMatchStore() {
		for (CredentialRequest cred : credentials)
			if (!cred.attributesMatchStore())
				return false;

		return true;
	}
}
