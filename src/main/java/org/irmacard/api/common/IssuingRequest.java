package org.irmacard.api.common;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.credentials.info.KeyException;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

@SuppressWarnings("unused")
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

	@Override
	public HashSet<CredentialIdentifier> getCredentialList() {
		HashSet<CredentialIdentifier> creds = new HashSet<>();

		for (CredentialRequest cred : credentials)
			creds.add(cred.getIdentifier());

		for (AttributeDisjunction disjunction : getRequiredAttributes())
			for (AttributeIdentifier attr : disjunction)
				creds.add(attr.getCredentialIdentifier());

		return creds;
	}

	@Override
	public HashMap<IssuerIdentifier, Integer> getPublicKeyList() {
		HashMap<IssuerIdentifier, Integer> map = new HashMap<>();

		for (CredentialRequest cred : credentials)
			map.put(cred.getIdentifier().getIssuerIdentifier(), cred.getKeyCounter());

		return map;
	}

	public AttributeDisjunctionList getRequiredAttributes() {
		if (disclose == null)
			disclose = new AttributeDisjunctionList();

		return disclose;
	}

	@Override
	public IdemixSystemParameters getLargestParameters() {
		IdemixSystemParameters largest = null;

		for (CredentialRequest cred : credentials) {
			try {
				if (largest == null || largest.get_l_n() < cred.getPublicKey().getBitsize())
					largest = cred.getPublicKey().getSystemParameters();

				for (AttributeDisjunction d : getRequiredAttributes()) {
					for (AttributeIdentifier ai : d) {
						IdemixPublicKey pk = IdemixKeyStore.getInstance().getLatestPublicKey(ai.getIssuerIdentifier());
						if (largest.get_l_n() < pk.getBitsize())
							largest = pk.getSystemParameters();
					}
				}

			} catch (KeyException e) {
				throw new RuntimeException(e);
			}
		}

		return largest;
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
