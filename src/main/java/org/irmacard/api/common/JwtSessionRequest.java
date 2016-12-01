package org.irmacard.api.common;

import org.irmacard.credentials.info.IssuerIdentifier;

import java.math.BigInteger;
import java.util.HashMap;

public class JwtSessionRequest {
	private String jwt;
	private BigInteger nonce;
	private BigInteger context;
	private HashMap<IssuerIdentifier, Integer> keys;

	public JwtSessionRequest(String jwt, BigInteger nonce, BigInteger context) {
		this.jwt = jwt;
		this.nonce = nonce;
		this.context = context;
	}

	public JwtSessionRequest(String jwt, BigInteger nonce, BigInteger context, HashMap<IssuerIdentifier, Integer> keys) {
		this(jwt, nonce, context);
		this.keys = keys;
	}

	public String getJwt() {
		return jwt;
	}

	public BigInteger getNonce() {
		return nonce;
	}

	public BigInteger getContext() {
		return context;
	}

	public HashMap<IssuerIdentifier, Integer> getPublicKeys() {
		return keys;
	}
}
