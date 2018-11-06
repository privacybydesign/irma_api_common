package org.irmacard.api.common.util;

import com.google.gson.*;
import org.irmacard.api.common.IrmaDisclosure;
import org.irmacard.credentials.idemix.proofs.ProofList;
import java.lang.System;

import java.lang.reflect.Type;

public class IrmaDisclosureSerializer implements JsonSerializer<IrmaDisclosure>, JsonDeserializer<IrmaDisclosure> {
	@Override
	public IrmaDisclosure deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		return new IrmaDisclosure((ProofList)context.deserialize(json, ProofList.class));
	}

	@Override
	public JsonElement serialize(IrmaDisclosure src, Type typeOfSrc, JsonSerializationContext context) {
		return context.serialize(src.getProofs());
	}
}
