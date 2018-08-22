package org.irmacard.api.common.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.api.common.ProtocolVersion;
import org.irmacard.credentials.idemix.proofs.Proof;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.CredentialIdentifier;

import java.text.DateFormat;
import java.util.HashMap;
import java.util.Map;

public class GsonUtilBuilder {
	boolean shouldReload;
	private HashMap<Class, Object> adapters = new HashMap<>();

	public GsonUtilBuilder() {
		adapters.put(byte[].class, new ByteArrayToBase64TypeAdapter());
		adapters.put(AttributeDisjunction.class, new AttributeDisjuctionSerializer());
		adapters.put(Proof.class, new ProofSerializer());
		adapters.put(CredentialIdentifier.class, new CredentialIdentifierSerializer());
		adapters.put(AttributeIdentifier.class, new AttributeIdentifierSerializer());
		adapters.put(ProtocolVersion.class, new ProtocolVersionSerializer());
		shouldReload = true;
	}

	/**
	 * Add the specified type adapter for the specified class.
	 */
	public void addTypeAdapter(Class clazz, Object o) {
		adapters.put(clazz, o);
		shouldReload = true;
	}

	public boolean shouldReload() {
		return shouldReload;
	}

	public Gson create() {
		GsonBuilder builder = new GsonBuilder();
		for (Map.Entry<Class, Object> entry : adapters.entrySet())
			builder.registerTypeAdapter(entry.getKey(), entry.getValue());

		builder.enableComplexMapKeySerialization();
		builder.setDateFormat(DateFormat.LONG, DateFormat.LONG);
		builder.disableHtmlEscaping();
		shouldReload = false;
		return builder.create();
	}
}
