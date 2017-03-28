package org.irmacard.api.common;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.irmacard.api.common.disclosure.DisclosureProofRequest;
import org.irmacard.api.common.disclosure.ServiceProviderRequest;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.apache.commons.codec.binary.Base64;

import org.irmacard.api.common.issuing.IssuingRequest;
import org.irmacard.api.common.issuing.IdentityProviderRequest;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;

/**
 * Issuing client for the irma_api_server.
 */
public class ApiClient {

    public static String getIssuingJWT(HashMap<CredentialIdentifier, HashMap<String, String>> credentialList, String iss, boolean shouldSign, SignatureAlgorithm sigAlg, PrivateKey privKey) {
        return shouldSign ?
                getSignedIssuingJWT(credentialList,iss,sigAlg, privKey) :
                getUnsignedIssuingJWT(credentialList,iss);
    }

    public static String getSignedIssuingJWT(HashMap<CredentialIdentifier, HashMap<String, String>> credentialList, String iss, SignatureAlgorithm sigAlg, PrivateKey privKey) {
        return Jwts.builder()
                .setPayload(getJwtClaims(credentialList,iss))
                .signWith(sigAlg,
                        privKey)
                .compact();
    }

    public static String getUnsignedIssuingJWT(HashMap<CredentialIdentifier, HashMap<String, String>> credentialList, String iss) {
        String header = encodeBase64("{\"typ\":\"JWT\",\"alg\":\"none\"}");
        String claims = encodeBase64(getJwtClaims(credentialList, iss));
        return header + "." + claims + ".";
    }

    public static String getDisclosureJWT(AttributeDisjunctionList list, String keyID, String iss, SignatureAlgorithm sigAlg, PrivateKey privKey) {
        DisclosureProofRequest request = new DisclosureProofRequest(null, null, list);
        ServiceProviderRequest spRequest = new ServiceProviderRequest("", request, 120);

        return Jwts.builder()
                .setHeaderParam("kid", keyID)
                .setPayload(getJwtClaims(spRequest, "sprequest", "verification_request",iss))
                .signWith(sigAlg,
                        privKey)
                .compact();
    }


    /**
     * Serialize the credentials to be issued to the body (claims) of a JWT token
     */
    //TODO: remove following code duplication:
    private static String getJwtClaims(HashMap<CredentialIdentifier, HashMap<String, String>> credentialList, String iss) {
        HashMap<String, Object> claims = new HashMap<>(4);
        claims.put("iprequest", getIdentityProviderRequest(credentialList));
        claims.put("iat", System.currentTimeMillis()/1000);
        claims.put("iss", iss);
        claims.put("sub", "issue_request");

        return GsonUtil.getGson().toJson(claims);
    }

    /**
     * Serialize the credentials to be issued to the body (claims) of a JWT token
     */
    private static String getJwtClaims(ClientRequest request,
                                       String type,
                                       String subject,
                                       String iss) {
        HashMap<String, Object> claims = new HashMap<>(4);
        claims.put(type, request);
        claims.put("iat", System.currentTimeMillis() / 1000);
        claims.put("iss", iss);
        claims.put("sub", subject);

        return GsonUtil.getGson().toJson(claims);
    }


        /**
         * Convert the credentials to be issued to an {@link IdentityProviderRequest} for the API server
         */
    public static IdentityProviderRequest getIdentityProviderRequest(HashMap<CredentialIdentifier, HashMap<String, String>> credentialList) {
        // Calculate expiry date: 6 months from now
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, 6);
        long validity = (calendar.getTimeInMillis() / Attributes.EXPIRY_FACTOR) * Attributes.EXPIRY_FACTOR / 1000;

        // Compute credential list for in the issuing request
        ArrayList<CredentialRequest> credentials = new ArrayList<>(credentialList.size());
        for (CredentialIdentifier identifier : credentialList.keySet())
            credentials.add(new CredentialRequest((int) validity, identifier, credentialList.get(identifier)));

        // Create issuing request, encode as unsigned JWT
        IssuingRequest request = new IssuingRequest(null, null, credentials);
        return new IdentityProviderRequest("", request, 120);
    }

    private static String encodeBase64(String data) {
        return Base64.encodeBase64String(data.getBytes())
                .replace('+', '-')
                .replace('/', '_')
                .replace("=", "")
                .replace("\n", "");
    }
}
