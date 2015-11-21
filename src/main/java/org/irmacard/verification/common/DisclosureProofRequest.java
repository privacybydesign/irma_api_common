/*
 * DisclosureProofRequest.java
 *
 * Copyright (c) 2015, Sietse Ringers, Radboud University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the IRMA project nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.verification.common;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.VerificationDescription;
import org.irmacard.verification.common.util.GsonUtil;
import org.irmacard.verification.common.DisclosureProofResult.Status;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.*;

public class DisclosureProofRequest implements Serializable {
	private static final long serialVersionUID = 1016467840623150897L;

	private BigInteger nonce;
	private BigInteger context;
	private List<AttributeDisjunction> content;

	public DisclosureProofRequest(BigInteger nonce, BigInteger context, List<AttributeDisjunction> content) {
		this.nonce = nonce;
		this.context = context;
		this.content = content;
	}

	/**
	 * Generate a request from a VerificationDescription.
	 */
	public DisclosureProofRequest(VerificationDescription vd) {
		content = new ArrayList<>(4);

		String issuer = vd.getIssuerID();
		String credential = vd.getCredentialID();

		CredentialDescription cd = vd.getCredentialDescription();
		for (String name : cd.getAttributeNames())
			if (vd.isDisclosed(name))
				content.add(new AttributeDisjunction(name, issuer + "." + credential + "." + name));

		context = Crypto.sha256Hash(vd.toString().getBytes()); // See IdemixVerificationDescription.java
		nonce = generateNonce();
	}

	public List<AttributeDisjunction> getContent() {
		return content;
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

	public DisclosureProofResult verify(ProofD proof) throws InfoException {
		DisclosureProofResult result = new DisclosureProofResult(); // Our return object

		if (!isSimple())
			throw new IllegalStateException("Non-simple requests not yet supported");

		AttributeIdentifier ai = content.get(0).get(0);
		String issuerName = ai.getIssuerName();
		String credentialName = ai.getCredentialName();

		IdemixPublicKey pk = IdemixKeyStore.getInstance().getPublicKey(issuerName);

		// The rest of this method partially duplicates IRMAIdemixDisclosureProof.verify(). Can't be helped: we
		// don't have a VerificationDescription handy here.

		// First check for validity (attribute 1 is metadata which must always be disclosed)
		if (proof == null || !proof.verify(pk, context, nonce) || proof.getDisclosedAttributes().get(1) == null) {
			result.setStatus(Status.INVALID);
			return result;
		}

		BigInteger metadata = proof.getDisclosedAttributes().get(1);
		short id = Attributes.extractCredentialId(metadata);
		if (!Attributes.isValid(metadata)) {
			result.setStatus(Status.EXPIRED);
			return result;
		}

		HashMap<String, String> attributes = new HashMap<>();
		result.setAttributes(attributes);

		CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescription(id);
		if (cd == null) {
			// If the id was not found in DescriptionStore, then whatever attributes are contained in the proof belong
			// to a credential type we don't know.
			result.setStatus(Status.MISSING_ATTRIBUTES);
			return result;
		}

		// Lookup the requested attributes in the proof
		for (AttributeDisjunction disjunction : getContent()) {
			String name = disjunction.get(0).getAttributeName();
			int index = cd.getAttributeNames().indexOf(name);
			if (index == -1) {
				result.setStatus(Status.MISSING_ATTRIBUTES);
				return result;
			}

			BigInteger attribute = proof.getDisclosedAttributes().get(index + 2); // + 2: skip secret key and metadata
			if (attribute == null) {
				result.setStatus(Status.MISSING_ATTRIBUTES);
				return result;
			}

			String value = new String(attribute.toByteArray());
			attributes.put(issuerName + "." + credentialName + "." + name, value);
		}

		return result;
	}

	/**
	 * Returns true if the request contains no disjunctions, and asks for attributes of a single credential type
	 */
	public boolean isSimple() {
		Set<String> credentials = new HashSet<>();

		for (AttributeDisjunction d : content) {
			if (d.size() > 1)
				return false;
			credentials.add(d.get(0).getCredentialName());
		}

		return credentials.size() == 1;
	}

	public static BigInteger generateNonce() {
		return new BigInteger(new IdemixSystemParameters().l_statzk, new Random());
	}

	@Override
	public String toString() {
		return toString(true);
	}

	public String toString(boolean includeContext) {
		BigInteger context = this.context;
		if (!includeContext)
			this.context = null;

		String val = GsonUtil.getGson().toJson(this);

		this.context = context;

		return val;
	}
}
