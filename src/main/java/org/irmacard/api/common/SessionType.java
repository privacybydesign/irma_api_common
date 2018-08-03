package org.irmacard.api.common;

import com.google.gson.annotations.SerializedName;

public enum SessionType {
	@SerializedName("disclosing") DISCLOSING,
	@SerializedName("issuing") ISSUING,
	@SerializedName("signing") SIGNING,
	UNKNOWN
}
