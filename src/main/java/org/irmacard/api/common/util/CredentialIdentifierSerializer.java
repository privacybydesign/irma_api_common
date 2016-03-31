package org.irmacard.api.common.util;

import com.google.gson.*;
import org.irmacard.credentials.idemix.proofs.Proof;
import org.irmacard.credentials.info.CredentialIdentifier;

import java.lang.reflect.Type;

public class CredentialIdentifierSerializer  implements JsonSerializer<CredentialIdentifier>, JsonDeserializer<CredentialIdentifier> {
	@Override
	public CredentialIdentifier deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		try {
			return new CredentialIdentifier(json.getAsJsonPrimitive().getAsString());
		} catch (IllegalArgumentException e) {
			throw new JsonParseException(e);
		}
	}

	@Override
	public JsonElement serialize(CredentialIdentifier src, Type typeOfSrc, JsonSerializationContext context) {
		return context.serialize(src.toString());
	}
}
