package org.irmacard.api.common;

import java.math.BigInteger;
import java.util.ArrayList;

public class IssuingRequest extends SessionRequest {
	private static final long serialVersionUID = -1702838649530088365L;

	private ArrayList<CredentialRequest> credentials;
	private AttributeDisjunctionList disclose = new AttributeDisjunctionList();

	public IssuingRequest(BigInteger nonce, BigInteger context, ArrayList<CredentialRequest> credentials) {
		super(nonce, context);
		this.credentials = credentials;
	}

	public ArrayList<CredentialRequest> getCredentials() {
		return credentials;
	}

	public AttributeDisjunctionList getRequiredAttributes() {
		if (disclose == null)
			disclose = new AttributeDisjunctionList();

		return disclose;
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
