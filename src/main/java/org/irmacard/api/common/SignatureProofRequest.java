package org.irmacard.api.common;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.proofs.Proof;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.api.common.DisclosureProofResult.Status;
import org.irmacard.credentials.info.KeyException;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class SignatureProofRequest extends DisclosureRequest {
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

        DisclosureProofResult d = super.verify(proofs, getChallenge());

        result.setStatus(d.getStatus());
        return result;
    }

    public String getMessage() {
        return message;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    /**
     * Calculate Challenge for signature as in paper:
     * @return challenge = H(commitment, h(msg))
     * @throws InfoException
     */
    public BigInteger getChallenge() throws InfoException {
        byte[] commitment = getNonce().toByteArray();
        BigInteger messageHash;
        if (! messageType.equals(MessageType.STRING)) {
            throw new InfoException("Other message types than string are not supported yet!");
        } else {
            messageHash = Crypto.sha256Hash(message.getBytes());
        }
        BigInteger challenge = Crypto.sha256Hash(commitment, messageHash.toByteArray());
        return challenge;
    }
}
