package org.irmacard.api.common;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerDescription;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

public class CredentialRequest {
	private int validity = 6;
	private String credential;
	private HashMap<String, String> attributes;

	public CredentialRequest(int validity, String credential, HashMap<String, String> attributes) {
		this.validity = validity;
		this.credential = credential;
		this.attributes = attributes;
	}

	public HashMap<String, String> getAttributes() {
		return attributes;
	}

	public String getFullName() {
		return credential;
	}

	public String getIssuerName() {
		return credential.split("\\.")[0];
	}

	public String getCredentialName() {
		return credential.split("\\.")[1];
	}

	public int getValidity() {
		return validity;
	}

	public void setValidity(int validity) {
		this.validity = validity;
	}

	public CredentialDescription getCredentialDescription() throws InfoException {
		return DescriptionStore.getInstance().getCredentialDescriptionByName(
				getIssuerName(), getCredentialName());
	}

	public IssuerDescription getIssuerDescription() throws InfoException {
		return DescriptionStore.getInstance().getIssuerDescription(getIssuerName());
	}

	public IdemixPublicKey getPublicKey() throws InfoException {
		return IdemixKeyStore.getInstance().getPublicKey(getIssuerName());
	}

	/**
	 * Checks if the names and amount of the containing attributes match those from the description store.
	 */
	public boolean attributesMatchStore() {
		CredentialDescription cd;
		try {
			cd = getCredentialDescription();
		} catch (InfoException e) {
			return false;
		}

		List<String> storeAttributes = cd.getAttributeNames();
		if (storeAttributes.size() != getAttributes().size())
			return false;

		for (String attr : getAttributes().keySet())
			if (!storeAttributes.contains(attr))
				return false;

		return true;
	}

	/**
	 * Convert the attributes to BigIntegers, suitable for passing to the Idemix API.
	 * @return The BigIntegers
	 * @throws InfoException If the attribute names do not match the ones from the description store
	 */
	public List<BigInteger> convertToBigIntegers() throws InfoException {
		if (!attributesMatchStore())
			throw new InfoException("Incompatible credential types");

		CredentialDescription cd = getCredentialDescription();

		Attributes attributes = new Attributes();
		attributes.setCredentialID(cd.getId());

		Calendar expires = Calendar.getInstance();
		expires.add(Calendar.MONTH, getValidity());
		attributes.setExpireDate(expires.getTime());

		List<BigInteger> rawAttributes = new ArrayList<>();
		rawAttributes.add(new BigInteger(1, attributes.get(Attributes.META_DATA_FIELD)));

		for(int i = 0; i < cd.getAttributeNames().size(); i++) {
			String attrname = cd.getAttributeNames().get(i);
			rawAttributes.add(new BigInteger(1, getAttributes().get(attrname).getBytes()));
		}

		return rawAttributes;
	}
}
