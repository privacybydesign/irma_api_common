package org.irmacard.api.common;

public class SchemeManagerQr extends IrmaQr {
	String url;

	public SchemeManagerQr(String name, String url) {
		super("schememanager");
		this.url = url;
	}

	public String getUrl() {
		return url;
	}
}

