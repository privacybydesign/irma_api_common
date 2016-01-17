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

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.proofs.Proof;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.VerificationDescription;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.api.common.DisclosureProofResult.Status;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.*;

@SuppressWarnings("unused")
public class DisclosureProofRequest extends SessionRequest {
	private static final long serialVersionUID = 1016467840623150897L;

	private List<AttributeDisjunction> content;

	public DisclosureProofRequest(BigInteger nonce, BigInteger context, List<AttributeDisjunction> content) {
		super(nonce, context);
		this.content = content;
	}

	/**
	 * Generate a request from a VerificationDescription.
	 */
	public DisclosureProofRequest(VerificationDescription vd) {
		super(
				generateNonce(),
				Crypto.sha256Hash(vd.toString().getBytes()) // See IdemixVerificationDescription.java
		);
		content = new ArrayList<>(4);

		String issuer = vd.getIssuerID();
		String credential = vd.getCredentialID();

		CredentialDescription cd = vd.getCredentialDescription();
		for (String name : cd.getAttributeNames())
			if (vd.isDisclosed(name))
				content.add(new AttributeDisjunction(name, issuer + "." + credential + "." + name));
	}

	public List<AttributeDisjunction> getContent() {
		return content;
	}

	public AttributeDisjunction find(String s) {
		for (AttributeDisjunction disjuncion : content)
			if (disjuncion.contains(s))
				return disjuncion;

		return null;
	}

	public DisclosureProofResult verify(ProofList proofs) throws InfoException {
		DisclosureProofResult result = new DisclosureProofResult(); // Our return object
		HashMap<String, String> attributes = new HashMap<>();
		result.setAttributes(attributes);

		if (!proofs.verify(getContext(), getNonce(), true)) {
			System.out.println("Proofs did not verify");
			result.setStatus(Status.INVALID);
			return result;
		}

		for (Proof proof : proofs) {
			if (!(proof instanceof ProofD))
				continue;

			ProofD proofD = (ProofD) proof;

			// Check presence of metadata attribute
			if (proofD.getDisclosedAttributes().get(1) == null) {
				System.out.println("Metadata attribute missing");
				result.setStatus(Status.INVALID);
				return result;
			}

			// Verify validity, extract credential id from metadata attribute
			BigInteger metadata = proofD.getDisclosedAttributes().get(1);
			short id = Attributes.extractCredentialId(metadata);
			if (!Attributes.isValid(metadata)) {
				result.setStatus(Status.EXPIRED);
				return result;
			}

			CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescription(id);
			if (cd == null) {
				// If the id was not found in DescriptionStore, then whatever attributes are contained in the proof belong
				// to a credential type we don't know.
				System.out.println("CredentialDescription not found");
				result.setStatus(Status.MISSING_ATTRIBUTES);
				return result;
			}
			String issuer = cd.getIssuerID();
			String credName = cd.getCredentialID();

			for (int j : proofD.getDisclosedAttributes().keySet()) {
				String attributeName = (j == 1) ? "" : "." + cd.getAttributeNames().get(j - 2);
				String identifier = issuer + "." + credName + attributeName;

				// See if this disclosed attribute occurs in one of our disjunctions
				AttributeDisjunction disjunction = find(identifier);
				if (disjunction == null || disjunction.isSatisfied())
					continue;

				String attrValue = new String(proofD.getDisclosedAttributes().get(j).toByteArray());
				if (!disjunction.hasValues())
					disjunction.setSatisfied(true);
				else {
					AttributeIdentifier ai = new AttributeIdentifier(identifier);
					String requiredValue = disjunction.getValues().get(ai);
					if (requiredValue.equals(attrValue))
						disjunction.setSatisfied(true);
				}

				String value = (j == 1) ? "present" : attrValue;
				attributes.put(identifier, value);
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
