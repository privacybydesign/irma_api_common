package org.irmacard.api.common;

import org.irmacard.api.common.signatures.SignatureProofRequest;
import org.irmacard.api.common.signatures.SignatureProofResult;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;

import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

public class AttributeBasedSignature {
	private final int v = 1;
	private ProofList proofs;
	private BigInteger nonce;
	private BigInteger context;

	private transient Map<AttributeIdentifier, String> attributes;

	public AttributeBasedSignature(ProofList proofs, BigInteger nonce, BigInteger context) {
		this.proofs = proofs;
		this.nonce = nonce;
		this.context = context;
	}

	public Map<AttributeIdentifier, String> getAttributes() throws IllegalArgumentException, CredentialsException {
		if (attributes == null)
			attributes = proofs.getAttributes();

		return attributes;
	}

	public SignatureProofResult verify(String message) throws InfoException, KeyException {
		return verify(message, Calendar.getInstance().getTime(), true);
	}

	public SignatureProofResult verify(String message, Date validityDate) throws InfoException, KeyException {
		return verify(message, validityDate, false);
	}

	public SignatureProofResult verify(String message, Date validityDate, boolean allowExpired)
	throws InfoException, KeyException {
		proofs.populatePublicKeyArray();
		proofs.setSig(true); // Verify this as an ABS (as opposed to a disclosure proof list)

		SignatureProofRequest request = new SignatureProofRequest(nonce, context,
				new AttributeDisjunctionList(), message, SignatureProofRequest.MessageType.STRING);
		SignatureProofResult result = request.verify(proofs, validityDate, allowExpired);

		attributes = result.getAttributes();
		return result;
	}

	public ProofList getProofs() {
		return proofs;
	}

	public BigInteger getNonce() {
		return nonce;
	}

	public BigInteger getContext() {
		return context;
	}

	public int getVersion() {
		return v;
	}
}
