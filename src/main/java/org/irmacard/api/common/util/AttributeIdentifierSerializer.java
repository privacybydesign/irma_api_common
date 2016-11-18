package org.irmacard.api.common.util;

import com.google.gson.*;
import org.irmacard.credentials.info.AttributeIdentifier;

import java.lang.reflect.Type;

public class AttributeIdentifierSerializer implements JsonSerializer<AttributeIdentifier>, JsonDeserializer<AttributeIdentifier> {
	@Override
	public AttributeIdentifier deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		try {
			return new AttributeIdentifier(json.getAsJsonPrimitive().getAsString());
		} catch (IllegalArgumentException|IllegalStateException e) {
			throw new JsonParseException(e);
		}
	}

	@Override
	public JsonElement serialize(AttributeIdentifier src, Type typeOfSrc, JsonSerializationContext context) {
		return context.serialize(src.toString());
	}
}
