package org.irmacard.verification.common;

public class DisclosureQr {
	private String u;
	private String v;

	DisclosureQr(String version, String url) {
		v = version;
		u = url;
	}

	public String getVersion() {
		return v;
	}

	public String getUrl() {
		return u;
	}
}
