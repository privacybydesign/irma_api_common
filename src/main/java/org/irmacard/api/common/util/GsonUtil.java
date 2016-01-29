/*
 * GsonUtil.java
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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import net.sf.scuba.smartcards.ProtocolCommand;
import net.sf.scuba.smartcards.ProtocolResponse;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.credentials.idemix.proofs.Proof;

import java.util.HashMap;
import java.util.Map;

/**
 * Keeps a {@link Gson} instance to which type adapters can be added
 * via {@link #addTypeAdapter(Class, Object)}.
 */
public class GsonUtil {
	protected static Gson gson;
	private static boolean shouldReload;
	private static HashMap<Class, Object> adapters = new HashMap<>();

	// Put in the (de)serialisers that we know of
	static {
		adapters.put(byte[].class, new ByteArrayToBase64TypeAdapter());
		adapters.put(AttributeDisjunction.class, new AttributeDisjuctionSerializer());
		adapters.put(Proof.class, new ProofSerializer());
		shouldReload = true;
	}

	private static void reload() {
		GsonBuilder builder = new GsonBuilder();
		for (Map.Entry<Class, Object> entry : adapters.entrySet())
			builder.registerTypeAdapter(entry.getKey(), entry.getValue());

		gson = builder.create();
		shouldReload = false;
	}

	/**
	 * Add the specified type adapter for the specified class.
	 */
	public static void addTypeAdapter(Class clazz, Object o) {
		adapters.put(clazz, o);
		shouldReload = true;
	}

	public static Gson getGson() {
		if (shouldReload)
			reload();

		return gson;
	}
}
