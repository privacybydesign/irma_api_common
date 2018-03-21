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

public class IrmaSignedMessage {
	private final int v = 1;
	private ProofList signature;
	private BigInteger nonce;
	private BigInteger context;
	private String message;

	private transient Map<AttributeIdentifier, String> attributes;

	public IrmaSignedMessage(ProofList proofs, BigInteger nonce, BigInteger context, String message) {
		this.signature = proofs;
		this.nonce = nonce;
		this.context = context;
		this.message = message;
	}

	public Map<AttributeIdentifier, String> getAttributes() throws IllegalArgumentException {
		if (attributes == null)
			attributes = signature.getAttributes();

		return attributes;
	}

	public SignatureProofResult verify() throws InfoException, KeyException {
		return verify(Calendar.getInstance().getTime(), true);
	}

	public SignatureProofResult verify(Date validityDate) throws InfoException, KeyException {
		return verify(validityDate, false);
	}

	public SignatureProofResult verify(Date validityDate, boolean allowExpired)
	throws InfoException, KeyException {
		return verify(null, validityDate, allowExpired);
	}

	public SignatureProofResult verify(SignatureProofRequest request, Date validityDate, boolean allowExpired)
			throws InfoException, KeyException {
		signature.populatePublicKeyArray();
		signature.setSig(true); // Verify this as an ABS (as opposed to a disclosure proof list)

		// Verify with 'empty' request if request was not set
		if (request == null) {
			request = new SignatureProofRequest(nonce, context,
					new AttributeDisjunctionList(), message);
		}

		SignatureProofResult result = request.verify(signature, validityDate, allowExpired);

		attributes = result.getAttributes();
		return result;
	}

	public String getMessage() {
		return message;
	}

	public ProofList getProofs() {
		return signature;
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
