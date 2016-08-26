package org.irmacard.api.common;

import java.math.BigInteger;

public class JwtSessionRequest {
	private String jwt;
	private BigInteger nonce;
	private BigInteger context;

	public JwtSessionRequest(String jwt, BigInteger nonce, BigInteger context) {
		this.jwt = jwt;
		this.nonce = nonce;
		this.context = context;
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
}
