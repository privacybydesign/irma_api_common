package org.irmacard.api.common;

import org.irmacard.api.common.AttributeDisjunction;

import java.io.Serializable;
import java.util.ArrayList;

public class AttributeDisjunctionList extends ArrayList<AttributeDisjunction> implements Serializable {
	private static final long serialVersionUID = -8772049946425958270L;

	public AttributeDisjunctionList() {
		super();
	}

	public AttributeDisjunctionList(int capacity) {
		super(capacity);
	}

	/**
	 * Returns true if each disjunction has a selected attribute.
	 */
	public boolean haveSelected() {
		for (AttributeDisjunction disjunction : this)
			if (disjunction.getSelected() == null)
				return false;

		return true;
	}

	/**
	 * Returns the disjuction containing the specified attribute, if present; null otherwise.
	 */
	public AttributeDisjunction find(AttributeIdentifier ai) {
		for (AttributeDisjunction disjunction : this)
			if (disjunction.contains(ai))
				return disjunction;

		return null;
	}

	/**
	 * Returns the disjuction containing the specified attribute, if present; null otherwise.
	 */
	public AttributeDisjunction find(String attribute) {
		return find(new AttributeIdentifier(attribute));
	}
}
