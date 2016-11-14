package org.irmacard.api.common;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.proofs.Proof;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.info.AttributeIdentifier;

import java.math.BigInteger;
import java.util.HashMap;

public class AttributeBasedSignature {
	private ProofList proofs;
	private BigInteger nonce;
	private BigInteger context;

	private transient HashMap<AttributeIdentifier, String> attributes;

	public AttributeBasedSignature(ProofList proofs, BigInteger nonce, BigInteger context) {
		this.proofs = proofs;
		this.nonce = nonce;
		this.context = context;
	}

	public HashMap<AttributeIdentifier, String> getAttributes() {
		if (attributes != null)
			return attributes;

		attributes = new HashMap<>();
		ProofD disclosure;
		Attributes attrs;

		for (Proof proof : proofs) {
			if (!(proof instanceof ProofD))
				throw new IllegalStateException("Non-ProofD found in signature");

			attrs = new Attributes(((ProofD) proof).get_a_disclosed());
			for (String attrname : attrs.getIdentifiers())
				attributes.put(new AttributeIdentifier(attrs.getCredentialIdentifier(), attrname), new String(attrs.get(attrname)));
		}

		return attributes;
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
}
