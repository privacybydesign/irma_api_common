package org.irmacard.api.common.signatures;

import org.irmacard.api.common.AttributeDisjunctionList;
import org.irmacard.api.common.disclosure.DisclosureProofRequest;
import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;

import java.math.BigInteger;

@SuppressWarnings("unused")
public class SignatureProofRequest extends DisclosureProofRequest {
    public enum MessageType { STRING
    }
    private String message;
    private MessageType messageType;


    public SignatureProofRequest(BigInteger nonce, BigInteger context,
                                 AttributeDisjunctionList content, String message, MessageType messageType) {
        super(nonce, context, content);
        this.message = message;
        this.messageType = messageType;
    }

    @Override
    public SignatureProofResult verify(ProofList proofs) throws KeyException, InfoException {
        proofs.setSig(true); // Make sure we're verifying a signature
        SignatureProofResult result = new SignatureProofResult(proofs, this); // Our return object

        DisclosureProofResult d = super.verify(proofs);
        result.setStatus(d.getStatus());

        if (d.getStatus() == DisclosureProofResult.Status.VALID) {
            try {
                result.setAttributes(proofs.getAttributes());
            } catch (CredentialsException e) {
                // Will not happen; in this case d.getStatus() would not be VALID
                throw new InfoException(e);
            }
        }

        return result;
    }

    public String getMessage() {
        return message;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    /**
     * Calculate nonce for the proofs of knowledge as determined by the nonce received by the server
     * (see {@link #getSignatureNonce()}).
     * @return proofsnonce = H(servernonce, H(msg))
     * @throws IllegalArgumentException if the message type is not STRING
     */
    @Override
    public BigInteger getNonce() {
        if (messageType != MessageType.STRING)
            throw new IllegalArgumentException("Other message types than string are not supported yet!");

        BigInteger messageHash = Crypto.sha256Hash(message.getBytes());
        return Crypto.sha256Hash(Crypto.asn1Encode(nonce, messageHash));
    }

    /**
     * Get the nonce (to be hashed along with the message, as in {@link #getNonce()}).
     */
    public BigInteger getSignatureNonce() {
        return nonce;
    }
}
