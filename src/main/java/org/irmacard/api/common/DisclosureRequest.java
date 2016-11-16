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

package org.irmacard.api.common;

import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.api.common.disclosure.DisclosureProofResult.Status;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.proofs.Proof;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.info.*;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * Generic disclosure request, can either be a normal disclosure proof or a signature proof
 */
@SuppressWarnings("unused")
public abstract class DisclosureRequest extends SessionRequest {
	private static final long serialVersionUID = 1016467840623150897L;

	protected AttributeDisjunctionList content;

	public DisclosureRequest(BigInteger nonce, BigInteger context, AttributeDisjunctionList content) {
		super(nonce, context);
		this.content = content;
	}

	public AttributeDisjunctionList getContent() {
		return content;
	}

	@Override
	public HashSet<CredentialIdentifier> getCredentialList() {
		HashSet<CredentialIdentifier> credentials = new HashSet<>();

		for (AttributeDisjunction disjunction : content)
			for (AttributeIdentifier attr : disjunction)
				credentials.add(attr.getCredentialIdentifier());

		return credentials;
	}

	@Override
	public HashMap<IssuerIdentifier, Integer> getPublicKeyList() {
		return new HashMap<>();
	}

	public boolean attributesMatchStore() throws ApiException {
		for (AttributeDisjunction disjunction : getContent())
			if (!disjunction.attributesMatchStore())
				return false;

		return true;
	}

	@Override
	public IdemixSystemParameters getLargestParameters() {
		IdemixSystemParameters params = null;

		for (AttributeDisjunction disjunction : getContent()) {
			for (AttributeIdentifier identifier : disjunction) {

				try {
					IdemixPublicKey pk = IdemixKeyStore.getInstance()
							.getLatestPublicKey(identifier.getIssuerIdentifier());
					if (params == null || params.get_l_n() < pk.getBitsize())
						params = pk.getSystemParameters();
				} catch (KeyException e) {
					throw new RuntimeException(e);
				}
			}
		}

		return params;
	}

	@Override
	public boolean isEmpty() {
		return content == null || content.size() == 0;
	}

	public abstract DisclosureProofResult verify(ProofList proofs) throws InfoException, KeyException;

	protected DisclosureProofResult verify(ProofList proofs, BigInteger nonce) throws InfoException, KeyException {
		DisclosureProofResult result = new DisclosureProofResult(); // Our return object
		HashMap<String, String> attributes = new HashMap<>();
		result.setAttributes(attributes);

		if (!proofs.verify(getContext(), nonce, true)) {
			System.out.println("Proofs did not verify");
			result.setStatus(Status.INVALID);
			return result;
		}

		for (Proof proof : proofs) {
			if (!(proof instanceof ProofD))
				continue;

			ProofD proofD = (ProofD) proof;
			Attributes disclosed;
			try {
				disclosed = new Attributes(proofD.getDisclosedAttributes());
			} catch (IllegalArgumentException e) {
				System.out.println("Metadata attribute missing");
				result.setStatus(Status.INVALID);
				return result;
			}

			// Verify validity, extract credential id from metadata attribute
			if (!disclosed.isValid()) {
				result.setStatus(Status.EXPIRED);
				return result;
			}

			CredentialIdentifier credId = disclosed.getCredentialIdentifier();
			if (credId == null) {
				System.out.println("Received unknown credential type");
				result.setStatus(Status.MISSING_ATTRIBUTES);
				return result;
			}

			// For each of the disclosed attributes in this proof, see if they satisfy one of
			// the AttributeDisjunctions that we asked for
			for (String attributeName : disclosed.getIdentifiers()) {
				String identifier;
				String value;
				if (!attributeName.equals(Attributes.META_DATA_FIELD)) {
					identifier = credId.toString() + "." + attributeName;
					value = new String(disclosed.get(attributeName));
				} else {
					identifier = credId.toString();
					value = "present";
				}

				attributes.put(identifier, value);

				// See if this disclosed attribute occurs in one of our disjunctions
				AttributeDisjunction disjunction = content.find(identifier);
				if (disjunction == null || disjunction.isSatisfied())
					continue;

				if (!disjunction.hasValues())
					disjunction.setSatisfied(true);
				else {
					// If the request indicated that the attribute should have a specific value, then the containing
					// disjunction is only satisfied if the actual value of the attribute is correct.
					AttributeIdentifier ai = new AttributeIdentifier(identifier);
					String requiredValue = disjunction.getValues().get(ai);
					if (requiredValue.equals(value))
						disjunction.setSatisfied(true);
				}
			}
		}

		for (AttributeDisjunction disjunction : content)
			if (!disjunction.isSatisfied())
				result.setStatus(Status.MISSING_ATTRIBUTES);

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
}
