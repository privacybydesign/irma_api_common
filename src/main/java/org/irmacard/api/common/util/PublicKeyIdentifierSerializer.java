package org.irmacard.api.common.util;

import com.google.gson.*;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.credentials.info.PublicKeyIdentifier;

import java.lang.reflect.Type;

public class PublicKeyIdentifierSerializer implements JsonSerializer<PublicKeyIdentifier>, JsonDeserializer<PublicKeyIdentifier> {
	@Override
	public PublicKeyIdentifier deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		String str = json.getAsJsonPrimitive().getAsString();
		int index = str.lastIndexOf("-");
		if (index == -1)
			throw new JsonParseException("Invalid PublicKeyIdentifier");
		IssuerIdentifier iss = new IssuerIdentifier(str.substring(0, index));
		try {
			int count = Integer.valueOf(str.substring(index + 1));
			return new PublicKeyIdentifier(iss, count);
		} catch (NumberFormatException e) {
			throw new JsonParseException("Invalid key counter", e);
		}
	}

	@Override
	public JsonElement serialize(PublicKeyIdentifier src, Type typeOfSrc, JsonSerializationContext context) {
		return context.serialize(src.getIssuer().toString() + "-" + src.getCounter());
	}
}
