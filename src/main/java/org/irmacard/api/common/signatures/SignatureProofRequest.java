package org.irmacard.api.common.signatures;

import org.irmacard.api.common.AttributeDisjunctionList;
import org.irmacard.api.common.disclosure.DisclosureProofRequest;
import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.api.common.disclosure.DisclosureProofResult.Status;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;

import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;

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

    public SignatureProofResult verify(ProofList proofs, boolean allowExpired) throws KeyException, InfoException {
        return verify(proofs, Calendar.getInstance().getTime(), allowExpired);
    }

    @Override
    public SignatureProofResult verify(ProofList proofs, Date validityDate, boolean allowExpired) throws KeyException, InfoException {
        proofs.setSig(true); // Make sure we're verifying a signature
        SignatureProofResult result = new SignatureProofResult(proofs, this); // Our return object

        DisclosureProofResult d = super.verify(proofs, validityDate, allowExpired);
        Status status = d.getStatus();
        result.setStatus(status);

        if (status == Status.VALID || (validityDate!=null && status == Status.EXPIRED)) {
            result.setAttributes(proofs.getAttributes());
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
