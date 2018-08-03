package org.irmacard.api.common;

import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.credentials.info.IssuerIdentifier;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;

@SuppressWarnings("unused")
public abstract class SessionRequest implements Serializable {
	private static final long serialVersionUID = -1765381227944439300L;

	protected BigInteger nonce;
	protected BigInteger context;
	protected SessionType type = SessionType.UNKNOWN;
	protected ProtocolVersion protocolVersion;

	public SessionRequest() {}

	public SessionRequest(BigInteger nonce, BigInteger context) {
		this.nonce = nonce;
		this.context = context;
	}

	public abstract HashSet<CredentialIdentifier> getCredentialList();

	public abstract HashMap<IssuerIdentifier, Integer> getPublicKeyList();

	public abstract IdemixSystemParameters getLargestParameters();

	public abstract boolean isEmpty();

	public HashSet<IssuerIdentifier> getIssuerList() {
		HashSet<IssuerIdentifier> issuers = new HashSet<>();

		for (CredentialIdentifier credential : getCredentialList())
			issuers.add(credential.getIssuerIdentifier());

		return issuers;
	}

	/**
	 * Get the scheme manager of the first credential in this session request.
	 * NOTE: we implicitly assume that all credentials are from the same manager, but we
	 * do not check that here.
	 */
	public String getSchemeManager() {
		return getCredentialList().iterator().next().getSchemeManagerName();
	}

	public BigInteger getNonce() {
		return nonce;
	}

	public void setNonce(BigInteger nonce) {
		this.nonce = nonce;
	}

	public BigInteger getContext() {
		return context;
	}

	public void setContext(BigInteger context) {
		this.context = context;
	}

	public ProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}

	public void setProtocolVersion(ProtocolVersion protocolVersion) {
		this.protocolVersion = protocolVersion;
	}

	public static BigInteger generateNonce(IdemixSystemParameters params) {
		return new BigInteger(params.get_l_statzk(), new SecureRandom());
	}

	public BigInteger generateContext() {
		return Crypto.sha256Hash(toString(false).getBytes());
	}

	public void setNonceAndContext() {
		this.nonce = generateNonce(getLargestParameters());
		this.context = generateContext();
	}

	@Override
	public String toString() {
		return toString(true);
	}

	public String toString(boolean includeContext) {
		BigInteger context = this.context;
		BigInteger nonce = this.nonce;
		if (!includeContext) {
			this.context = null;
			this.nonce = null;
		}

		String val = GsonUtil.getGson().toJson(this);

		this.context = context;
		this.nonce = nonce;

		return val;
	}
}
