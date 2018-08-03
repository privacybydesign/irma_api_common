package org.irmacard.api.common.util;

import com.google.gson.*;
import org.irmacard.api.common.ProtocolVersion;

import java.lang.reflect.Type;

public class ProtocolVersionSerializer implements JsonSerializer<ProtocolVersion>, JsonDeserializer<ProtocolVersion> {
	@Override
	public ProtocolVersion deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		try {
			return new ProtocolVersion(json.getAsJsonPrimitive().getAsString());
		} catch (IllegalArgumentException|IllegalStateException e) {
			throw new JsonParseException(e);
		}
	}

	@Override
	public JsonElement serialize(ProtocolVersion src, Type typeOfSrc, JsonSerializationContext context) {
		return context.serialize(src.toString());
	}
}
