package org.irmacard.api.common;

import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.api.common.SignatureProofRequest.MessageType;
import org.irmacard.credentials.idemix.proofs.ProofList;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class SignatureProofResult extends DisclosureProofResult {
    private AttributeBasedSignature signature;
    private String message;
    private MessageType messageType;

    public SignatureProofResult() {
        setStatus(Status.INVALID); // A signature without a signature is off course invalid
    }

    public SignatureProofResult(ProofList proofs, String message, MessageType messageType,
                                BigInteger nonce, BigInteger context) {
        setStatus(Status.VALID); // Note: we don't check the validity here!
        this.signature = new AttributeBasedSignature(proofs, nonce, context);
        this.message = message;
        this.messageType = messageType;
    }

    public SignatureProofResult(ProofList proofs, SignatureProofRequest request) {
        this(proofs, request.getMessage(), request.getMessageType(), request.getNonce(), request.getContext());
    }

    @Override
    public Map<String, Object> getAsMap() {
        HashMap<String, Object> map = new HashMap<>(4);
        map.put("status", getStatus());
        map.put("attributes", getAttributes());
        map.put("jti", getServiceProviderData());
        map.put("signature", signature);
        map.put("message", message);
        map.put("messageType", messageType.toString());
        return map;
    }

    public AttributeBasedSignature getSignature() {
        return signature;
    }

    public String getMessage() {
        return message;
    }

    public MessageType getMessageType() {
        return messageType;
    }
}
