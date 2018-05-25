package org.irmacard.api.common.signatures;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.encoders.Base64;
import org.irmacard.api.common.AttributeDisjunctionList;
import org.irmacard.api.common.disclosure.DisclosureProofRequest;
import org.irmacard.api.common.disclosure.DisclosureProofResult;
import org.irmacard.api.common.disclosure.DisclosureProofResult.Status;
import org.irmacard.api.common.timestamp.Timestamp;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;

@SuppressWarnings("unused")
public class SignatureProofRequest extends DisclosureProofRequest {
    private String message;
    private transient Timestamp timestamp;

    public SignatureProofRequest(BigInteger nonce, BigInteger context,
                                 AttributeDisjunctionList content, String message) {
        super(nonce, context, content);
        this.message = message;
    }

    public SignatureProofResult verify(ProofList proofs, boolean allowExpired) throws KeyException, InfoException {
        return verify(proofs, Calendar.getInstance().getTime(), allowExpired);
    }

    @Override
    public void setNonceAndContext() {
        if (this.nonce == null) {
            this.nonce = generateNonce(getLargestParameters());
        }
        if (this.context == null) {
            this.context = generateContext();
        }
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

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Calculate nonce for the proofs of knowledge as determined by the nonce received by the server
     * (see {@link #getSignatureNonce()}).
     * @return H(serverNonce, H(message), timestampSignature)
     */
    @Override
    public BigInteger getNonce() {
        BigInteger messageHash = Crypto.sha256Hash(message.getBytes());
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(nonce));
        vector.add(new ASN1Integer(messageHash));
        if (timestamp != null)
            vector.add(new DEROctetString(timestamp.Sig.Data));

        try {
            return Crypto.sha256Hash(new DERSequence(vector).getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Get the nonce (to be hashed along with the message, as in {@link #getNonce()}).
     */
    public BigInteger getSignatureNonce() {
        return nonce;
    }
}
