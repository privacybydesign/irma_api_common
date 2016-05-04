package org.irmacard.api.common;

import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.api.common.SignatureProofRequest.MessageType;
import org.irmacard.credentials.idemix.proofs.ProofList;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class SignatureProofResult extends DisclosureProofResult {

    private ProofList signature;
    private String message;
    private MessageType messageType;
    private BigInteger nonce;
    private BigInteger context;
    private AttributeDisjunctionList conditions;

    public SignatureProofResult() {
        setStatus(Status.INVALID); // A signature without a signature is off course invalid
    }

    public SignatureProofResult(SignatureProofRequest request) {

    }

    public SignatureProofResult(ProofList signature, String message, MessageType messageType,
                                BigInteger nonce, BigInteger context, AttributeDisjunctionList conditions) {
        this.signature = signature;
        setStatus(Status.VALID); // Note: we don't check the validity here!
        this.message = message;
        this.messageType = messageType;
        this.nonce = nonce;
        this.context = context;
        this.conditions = conditions;
    }

    public SignatureProofResult(ProofList signature, SignatureProofRequest request) {
        this(signature, request.getMessage(), request.getMessageType(), request.getNonce(),
                request.getContext(), request.getContent());
    }

    @Override
    public Map<String, Object> getAsMap() {
        HashMap<String, Object> map = new HashMap<>(4);
        map.put("status", getStatus());
        map.put("attributes", getAttributes());
        map.put("jti", getServiceProviderData());
        String sigString = GsonUtil.getGson().toJson(signature); // Otherwise we don't get valid json
        map.put("signature", sigString);
        map.put("message", message);
        map.put("messageType", messageType.toString());
        map.put("nonce", nonce);
        map.put("context", context);
        if (conditions != null) {
            String conditionString = GsonUtil.getGson().toJson(conditions);
            map.put("conditions", conditionString);
        }
        return map;
    }
}
