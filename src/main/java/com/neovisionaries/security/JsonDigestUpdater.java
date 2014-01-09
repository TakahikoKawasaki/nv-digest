/*
 * Copyright (C) 2014 Neo Visionaries Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.neovisionaries.security;


import static com.neovisionaries.security.Digest.Feature.IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_NULL;
import static com.neovisionaries.security.Digest.Feature.SORT_JSON_OBJECT_ENTRY_KEYS;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


/**
 * Implementation of {@link Digest#updateJson(String)}.
 *
 * @author Takahiko Kawasaki
 *
 * @since 1.1
 */
class JsonDigestUpdater
{
    private Digest digest;
    private StringBuilder path;
    private boolean ignoreJsonObjectEntryWithNull;
    private boolean sortJsonObjectEntryKeys;


    public Digest update(Digest digest, String json) throws IOException
    {
        // Set the digest to update.
        this.digest = digest;

        // Initialize the path.
        this.path = new StringBuilder();

        // Copy configuration.
        this.ignoreJsonObjectEntryWithNull = digest.isEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_NULL);
        this.sortJsonObjectEntryKeys = digest.isEnabled(SORT_JSON_OBJECT_ENTRY_KEYS);

        // Convert JSON to a node tree.
        JsonNode root = createTree(json);

        // Path start
        mark("P");

        // Traverse the node tree.
        update(root);

        // Path end
        mark("p");

        // Finally, update the digest with 'path' in order to prevent
        // different JSONs from generating the same digest accidentally.
        digest.update(path.toString());

        return digest;
    }


    private JsonNode createTree(String json) throws IOException
    {
        return createObjectMapper().readTree(json);
    }


    private ObjectMapper createObjectMapper()
    {
        ObjectMapper mapper = new ObjectMapper();

        mapper.configure(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS, true);

        return mapper;
    }


    private void mark(String mark)
    {
        path.append(mark);
    }


    private void update(JsonNode node)
    {
        if (node.isArray())
        {
            updateArray(node);
        }
        else if (node.isObject())
        {
            updateObject(node);
        }
        else if (node.isBoolean())
        {
            updateBoolean(node);
        }
        else if (node.isNumber())
        {
            updateNumber(node);
        }
        else if (node.isTextual())
        {
            updateText(node);
        }
        else if (node.isNull())
        {
            updateNull(node);
        }
        else if (node.isBinary())
        {
            // Probably, this won't happen.
            updateBinary(node);
        }
    }


    private void updateArray(JsonNode node)
    {
        // Array start.
        mark("A");

        // For each element.
        for (JsonNode element : node)
        {
            // Array element start.
            mark("E");

            // Update the digest with the element.
            update(element);

            // Array element end.
            mark("e");
        }

        // Array end.
        mark("a");
    }


    private void updateObject(JsonNode node)
    {
        // Object start.
        mark("O");

        // Field names.
        List<String> names = getFieldNames(node);

        // For each field name.
        for (String name : names)
        {
            // Get the value of the field.
            JsonNode value = node.findValue(name);

            // Update the digest with the pair of name and value.
            updateObjectEntry(name, value);
        }

        // Object end.
        mark("o");
    }


    private void updateObjectEntry(String name, JsonNode value)
    {
        if (ignoreJsonObjectEntryWithNull && value.isNull())
        {
            // The value of the field is null. Ignore this entry.
            return;
        }

        // Key start.
        mark("K");

        // Update the digest with the name.
        digest.update(name);

        // Key end and Value start.
        mark("kV");

        // Update the digest with the value.
        update(value);

        // Value end.
        mark("v");
    }


    private List<String> getFieldNames(JsonNode node)
    {
        // Generate a list of field names.
        List<String> list = iteratorToList(node.fieldNames());

        if (sortJsonObjectEntryKeys)
        {
            // Sort on field names.
            Collections.sort(list);
        }

        return list;
    }


    private <TElement> List<TElement> iteratorToList(Iterator<TElement> iterator)
    {
        List<TElement> list = new ArrayList<TElement>();

        while (iterator.hasNext())
        {
            list.add(iterator.next());
        }

        return list;
    }


    private void updateBoolean(JsonNode node)
    {
        // Boolean start.
        mark("B");

        digest.update(node.asBoolean());

        // "Boolean end.
        mark("b");
    }


    private void updateNumber(JsonNode node)
    {
        // Number start.
        mark("N");

        // Numbers contribute to the digest as String to make it
        // easy to implement JsonDigestUpdater equivalent for other
        // non-Java platforms.
        //
        // Note that BigDecimal.toString() is used for floating point
        // numbers because USE_BIG_DECIMAL_FOR_FLOATS is enabled.
        digest.update(node.toString());

        // Number end.
        mark("n");
    }


    private void updateText(JsonNode node)
    {
        // Text start.
        mark("T");

        digest.update(node.asText());

        // Text end.
        mark("t");
    }


    private void updateNull(JsonNode node)
    {
        // Null start.
        mark("<");

        digest.update("NULL");

        // Null end.
        mark(">");
    }


    private void updateBinary(JsonNode node)
    {
        // Binary start.
        mark("[");

        try
        {
            digest.update(node.binaryValue());
        }
        catch (IOException e)
        {
            // This won't happen because updateBinary(JsonNode)
            // is called only when node.isBinary() returns true.
        }

        // Binary end.
        mark("]");
    }
}
