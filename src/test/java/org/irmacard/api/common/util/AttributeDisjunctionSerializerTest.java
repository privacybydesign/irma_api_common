package org.irmacard.api.common.util;

import com.google.gson.Gson;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;

public class AttributeDisjunctionSerializerTest {

    @Test
    public void testSerialization() {
        AttributeIdentifier aid = new AttributeIdentifier("testIssuer.testCredential.testAttribute");
        AttributeDisjunction adj = new AttributeDisjunction("testDis", aid);
        Gson gson = GsonUtil.getGson();
        String expected = "{\"label\":\"testDis\",\"attributes\":[\"testIssuer.testCredential.testAttribute\"]}";
        String serialized = gson.toJson(adj);
        assertEquals("Serialized object and expected json string should be the same", expected, serialized);

        AttributeDisjunction deserialized = gson.fromJson(expected, AttributeDisjunction.class);

        assertEquals("Serialized and deserialized object should be the same", adj, deserialized);
    }
}
