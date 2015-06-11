/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @authors tag. All rights reserved.
 */
package org.keycloak.broker.oidc.mappers;

import java.io.IOException;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Assert;
import org.junit.Test;

/**
 * Unit test for {@link AbstractJsonUserAttributeMapper}
 * 
 * @author Vlastimil Elias (velias at redhat dot com)
 */
public class AbstractJsonUserAttributeMapperTest {

	private static ObjectMapper mapper = new ObjectMapper();

	private static JsonNode baseNode;

	private JsonNode getJsonNode() throws JsonProcessingException, IOException {
		if (baseNode == null)
			baseNode = mapper.readTree("{ \"value1\" : \"v1 \",\"value_empty\" : \"\", \"value_b\" : true, \"value_i\" : 454, " + " \"value_array\":[\"a1\",\"a2\"], " +" \"nest1\": {\"value1\": \" fgh \",\"value_empty\" : \"\", \"nest2\":{\"value_b\" : false, \"value_i\" : 43}}, "+ " \"nesta\": { \"a\":[{\"av1\": \"vala1\"},{\"av1\": \"vala2\"}]}"+" }");
		return baseNode;
	}

	@Test
	public void getJsonValue_invalidPath() throws JsonProcessingException, IOException {

		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "."));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), ".."));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "...value1"));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), ".value1"));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value1."));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "[]"));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "[value1"));
	}

	@Test
	public void getJsonValue_simpleValues() throws JsonProcessingException, IOException {

		//unknown field returns null
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_unknown"));
		
		// we check value is trimmed also!
		Assert.assertEquals("v1", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value1"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_empty"));

		Assert.assertEquals("true", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_b"));
		Assert.assertEquals("454", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_i"));

	}

	@Test
	public void getJsonValue_nestedSimpleValues() throws JsonProcessingException, IOException {

		// null if path points to JSON object
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1.nest2"));

		//unknown field returns null
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1.value_unknown"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1.nest2.value_unknown"));

		// we check value is trimmed also!
		Assert.assertEquals("fgh", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1.value1"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1.value_empty"));

		Assert.assertEquals("false", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1.nest2.value_b"));
		Assert.assertEquals("43", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1.nest2.value_i"));

		// null if invalid nested path
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1."));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nest1.nest2."));
	}

	@Test
	public void getJsonValue_simpleArray() throws JsonProcessingException, IOException {

		// array field itself returns null if no index is provided
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_array"));
		// outside index returns null
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_array[2]"));

		//corect index
		Assert.assertEquals("a1", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_array[0]"));
		Assert.assertEquals("a2", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_array[1]"));
		
		//incorrect array constructs
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_array[]"));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_array]"));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_array["));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_array[a]"));
		Assert.assertNull(AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "value_array[-2]"));
	}

	@Test
	public void getJsonValue_nestedArrayWithObjects() throws JsonProcessingException, IOException {
		Assert.assertEquals("vala1", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a[0].av1"));
		Assert.assertEquals("vala2", AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a[1].av1"));

		//different path erros or nonexisting indexes or fields return null
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a[2].av1"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a[0]"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a[0].av_unknown"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a[].av1"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a.av1"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a].av1"));
		Assert.assertEquals(null, AbstractJsonUserAttributeMapper.getJsonValue(getJsonNode(), "nesta.a[.av1"));
		
	}

}
