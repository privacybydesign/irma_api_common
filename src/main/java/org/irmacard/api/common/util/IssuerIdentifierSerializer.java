package org.irmacard.api.common.util;

import com.google.gson.*;
import org.irmacard.credentials.info.IssuerIdentifier;

import java.lang.reflect.Type;

public class IssuerIdentifierSerializer implements JsonSerializer<IssuerIdentifier>, JsonDeserializer<IssuerIdentifier> {
	@Override
	public IssuerIdentifier deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		try {
			return new IssuerIdentifier(json.getAsJsonPrimitive().getAsString());
		} catch (IllegalArgumentException|IllegalStateException e) {
			throw new JsonParseException(e);
		}
	}

	@Override
	public JsonElement serialize(IssuerIdentifier src, Type typeOfSrc, JsonSerializationContext context) {
		return context.serialize(src.toString());
	}
}
