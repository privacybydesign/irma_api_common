package org.irmacard.api.common;

import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.info.*;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

@SuppressWarnings("unused")
public class CredentialRequest implements Serializable {
	private static final long serialVersionUID = -8528619506484557225L;

	private long validity = getDefaultValidity();
	private int keyCounter;
	private CredentialIdentifier credential;
	private HashMap<String, String> attributes;

	public CredentialRequest() {}

	public CredentialRequest(int validity, CredentialIdentifier credential, HashMap<String, String> attributes) {
		this.validity = validity;
		this.credential = credential;
		this.attributes = attributes;
	}

	public static long getDefaultValidity() {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.MONTH, 6);
		return floorValidityDate(cal.getTimeInMillis(), true);
	}

	public static long floorValidityDate(long timestamp, boolean isMillis) {
		if (!isMillis)
			timestamp *= 1000;

		return (timestamp / Attributes.EXPIRY_FACTOR) * Attributes.EXPIRY_FACTOR / 1000;
	}

	public HashMap<String, String> getAttributes() {
		return attributes;
	}

	public String getFullName() {
		return credential.toString();
	}

	public CredentialIdentifier getIdentifier() {
		return credential;
	}

	public String getIssuerName() {
		return getIdentifier().getIssuerName();
	}

	public String getCredentialName() {
		return getIdentifier().getCredentialName();
	}

	public long getValidity() {
		return validity;
	}

	public long getValidity(boolean floored) {
		if (!floored)
			return validity;
		else
			return floorValidityDate(validity, false);
	}

	public void setValidity(int validity) {
		this.validity = validity;
	}

	public boolean isValidityFloored() {
		return getValidity(false) == getValidity(true);
	}

	public int getKeyCounter() {
		return keyCounter;
	}

	public void setKeyCounter(int keyCounter) {
		this.keyCounter = keyCounter;
	}

	public CredentialDescription getCredentialDescription() throws InfoException {
		return getIdentifier().getCredentialDescription();
	}

	public IssuerDescription getIssuerDescription() {
		return getIdentifier().getIssuerIdentifier().getIssuerDescription();
	}

	public IdemixPublicKey getPublicKey() throws KeyException {
		return IdemixKeyStore.getInstance().getPublicKey(getIdentifier().getIssuerIdentifier(), keyCounter);
	}

	/**
	 * Checks if the names and amount of the containing attributes match those from the description store.
	 */
	public boolean attributesMatchStore() {
		CredentialDescription cd;
		try {
			cd = getCredentialDescription();
		} catch (InfoException e) {
			throw new ApiException(ApiError.EXCEPTION, e.getMessage());
		}

		if (cd == null)
			return false;

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
		return convertToBigIntegers(true);
	}

	/**
	 * Convert the attributes to BigIntegers, suitable for passing to the Idemix API.
	 * @param floorValidity Whether or not to floor the validity date to an epoch boundary
	 * @return The BigIntegers
	 * @throws InfoException If the attribute names do not match the ones from the description store
	 */
	public List<BigInteger> convertToBigIntegers(boolean floorValidity) throws InfoException {
		if (!attributesMatchStore())
			throw new InfoException("Incompatible credential types");

		Attributes attributesObject = new Attributes();
		attributesObject.setSigningDate(Calendar.getInstance().getTime());
		attributesObject.setCredentialIdentifier(getIdentifier());
		attributesObject.setKeyCounter(getKeyCounter());
		Calendar expires = Calendar.getInstance();
		expires.setTimeInMillis(getValidity(floorValidity) * 1000);
		attributesObject.setExpiryDate(expires.getTime());

		for (String name : attributes.keySet()) {
			attributesObject.add(name, attributes.get(name).getBytes());
		}

		return attributesObject.toBigIntegers();
	}
}
