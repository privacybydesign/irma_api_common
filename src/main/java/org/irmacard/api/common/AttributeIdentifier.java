/*
 * AttributeIdentifier.java
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

package org.irmacard.api.common;

import java.io.Serializable;

@SuppressWarnings("unused")
public class AttributeIdentifier implements Serializable {
	private static final long serialVersionUID = 1158661160715464298L;

	private String identifier;

	public AttributeIdentifier() {
		identifier = "";
	}

	public AttributeIdentifier(String value) throws IllegalArgumentException {
		set(value);
	}

	public void set(String value) throws IllegalArgumentException {
		if (value == null || value.equals(""))
			throw new IllegalArgumentException("Invalid value: can't be null or empty");

		int length = value.split("\\.").length;
		if (length != 2 && length != 3)
			throw new IllegalArgumentException("Invalid value: must contain 2 or 3 parts separated by a dot (value: "
					+ value + ")");

		identifier = value;
	}

	public String[] split() {
		return identifier.split("\\.");
	}

	public String getIssuerName() {
		return split()[0];
	}

	public String getCredentialName() {
		return split()[1];
	}

	public String getAttributeName() {
		if (!isCredential())
			return split()[2];

		return null;
	}

	public boolean isCredential() {
		return split().length == 2;
	}

	@Override
	public String toString() {
		return identifier;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof AttributeIdentifier))
			return false;

		AttributeIdentifier i = (AttributeIdentifier) o;
		return (this.identifier.equals(i.identifier));
	}

	@Override
	public int hashCode() {
		return identifier.hashCode();
	}
}
