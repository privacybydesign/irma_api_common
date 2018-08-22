package org.irmacard.api.common.util;

import com.google.gson.*;
import org.bouncycastle.util.encoders.Base64;

import java.lang.reflect.Type;
import java.math.BigInteger;

public class Base64BigIntegerSerializer implements JsonSerializer<BigInteger>, JsonDeserializer<BigInteger> {
	@Override
	public BigInteger deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		try {
			return new BigInteger(1, Base64.decode(json.getAsJsonPrimitive().getAsString()));
		} catch (Exception e) {
			throw new JsonParseException("Failed parsing json into BigInteger", e);
		}
	}

	@Override
	public JsonElement serialize(BigInteger src, Type typeOfSrc, JsonSerializationContext context) {
		if (src.signum() == -1)
			throw new JsonSyntaxException("Cannot serialize negative bigint " + src.toString());
		return context.serialize(Base64.toBase64String(src.toByteArray()));
	}
}
