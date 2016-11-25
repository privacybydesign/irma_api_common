package org.irmacard.api.common;

public class IrmaQr {
	private String irmaqr;

	public IrmaQr(String irmaqr) {
		this.irmaqr = irmaqr;
	}

	public String getType() {
		return irmaqr;
	}
}
