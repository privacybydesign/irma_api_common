/*
 * AttributeDisjuctionSerializer.java
 *
 * Copyright (c) 2015, Sietse Ringers, Radboud University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the IRMA project nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.api.common.util;

import com.google.gson.*;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.api.common.AttributeIdentifier;

import java.lang.reflect.Type;

public class AttributeDisjuctionSerializer
		implements JsonSerializer<AttributeDisjunction>, JsonDeserializer<AttributeDisjunction> {
	@Override
	public JsonElement serialize(AttributeDisjunction src, Type typeOfSrc, JsonSerializationContext context) {
		JsonObject object = new JsonObject();
		JsonArray array = new JsonArray();

		for (AttributeIdentifier identifier : src)
			array.add(new JsonPrimitive(identifier.toString()));

		object.add("attributes", array);
		object.addProperty("label", src.getLabel());

		return object;
 	}

	@Override
	public AttributeDisjunction deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		try {
			JsonObject object = json.getAsJsonObject();
			String label = object.get("label").getAsString();

			AttributeDisjunction disjunction = new AttributeDisjunction(label);

			JsonArray array = object.get("attributes").getAsJsonArray();
			for (JsonElement el : array)
				disjunction.add(new AttributeIdentifier(el.getAsString()));

			return disjunction;
		} catch (IllegalStateException|ClassCastException|NullPointerException e) {
			throw new JsonParseException(e);
		}
	}
}
