package org.irmacard.api.common;

import org.irmacard.credentials.idemix.proofs.ProofList;

public class IrmaDisclosure {
	private ProofList proofs;

	public IrmaDisclosure(ProofList proofs) {
		this.proofs = proofs;
	}

	public ProofList getProofs() {
		return proofs;
	}
}
