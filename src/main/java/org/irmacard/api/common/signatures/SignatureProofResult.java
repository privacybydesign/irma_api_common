package org.irmacard.api.common.signatures;

import org.irmacard.api.common.IrmaSignedMessage;
import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.api.common.timestamp.Timestamp;
import org.irmacard.credentials.idemix.proofs.ProofList;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class SignatureProofResult extends DisclosureProofResult {
    private IrmaSignedMessage signature;

    public SignatureProofResult() {
        setStatus(Status.INVALID); // A signature without a signature is off course invalid
    }

    public SignatureProofResult(ProofList proofs, String message,
                                BigInteger nonce, BigInteger context, Timestamp timestamp) {
        setStatus(Status.VALID); // Note: we don't check the validity here!
        this.signature = new IrmaSignedMessage(proofs, nonce, context, message, timestamp);
    }

    public SignatureProofResult(ProofList proofs, SignatureProofRequest request) {
        this(proofs, request.getMessage(), request.getSignatureNonce(), request.getContext(), request.getTimestamp());
    }

    @Override
    public Map<String, Object> getAsMap() {
        HashMap<String, Object> map = new HashMap<>(4);
        map.put("status", getStatus());
        map.put("attributes", getAttributes());
        map.put("jti", getServiceProviderData());
        map.put("signature", signature);
        return map;
    }

    public IrmaSignedMessage getSignature() {
        return signature;
    }
}
