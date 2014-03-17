/*
 * Copyright (C) 2013-2014 Neo Visionaries Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;


public class DigestTest
{
    private Digest sha1()
    {
        return Digest.getInstanceSHA1();
    }


    private Digest md5()
    {
        return Digest.getInstanceMD5();
    }


    private void doJsonTest(String json1, String json2, Digest digest1, Digest digest2, boolean equals)
    {
        if (digest1 == null)
        {
            digest1 = sha1();
        }

        if (digest2 == null)
        {
            digest2 = sha1();
        }

        try
        {
            String result1 = digest1.updateJson(json1).digestAsString();
            String result2 = digest2.updateJson(json2).digestAsString();

            if (equals)
            {
                assertEquals(result1, result2);
            }
            else
            {
                assertThat(result1, not(result2));
            }
        }
        catch (IOException e)
        {
            fail(e.getLocalizedMessage());
        }
    }


    private void doJsonEquals(String json1, String json2)
    {
        doJsonTest(json1, json2, null, null, true);
    }


    private void doJsonNotEquals(String json1, String json2)
    {
        doJsonTest(json1, json2, null, null, false);
    }


    @Test
    public void test1()
    {
        String expected = "2ae01472317d1935a84797ec1983ae243fc6aa28";
        String actual = sha1().update("Hello, world.").digestAsString();

        assertEquals(expected, actual);
    }


    @Test
    public void test2()
    {
        List<Number> list = new ArrayList<Number>();
        list.add(new Byte((byte)1));
        list.add(new Short((short)2));
        list.add(new Integer(3));
        list.add(new Long(4));
        list.add(new Float(5));
        list.add(new Double(6));

        String digest1 = sha1().update(list).digestAsString();

        String digest2 = sha1()
                         .update((byte)1)
                         .update((short)2)
                         .update(3)
                         .update((long)4)
                         .update((float)5)
                         .update((double)6)
                         .digestAsString();

        assertEquals(digest1, digest2);
    }


    @Test
    public void test3()
    {
        List<String> list = new ArrayList<String>();
        list.add("Apple");
        list.add("Banana");
        list.add("Cherry");

        String digest1 = md5().update(list).digestAsString();

        String digest2 = md5()
                         .update("Apple")
                         .update("Banana")
                         .update("Cherry")
                         .digestAsString();

        assertEquals(digest1, digest2);
    }


    @Test
    public void test4()
    {
        String json1 = "{ \"key1\":1234567890.123456789 }";
        String json2 = "{ \"key1\":\"1234567890.123456789\" }";

        doJsonNotEquals(json1, json2);
    }


    @Test
    public void test5()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":\"value2\" }";
        String json2 = "{ \"key2\":\"value2\", \"key1\":\"value1\" }";

        doJsonEquals(json1, json2);
    }


    @Test
    public void test6()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":\"value2\" }";
        String json2 = "{ \"key2\":\"value2\", \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(SORT_JSON_OBJECT_ENTRY_KEYS, false);
        Digest digest2 = sha1().setEnabled(SORT_JSON_OBJECT_ENTRY_KEYS, false);

        doJsonTest(json1, json2, digest1, digest2, false);
    }


    @Test
    public void test7()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":null }";
        String json2 = "{ \"key1\":\"value1\" }";

        doJsonNotEquals(json1, json2);
    }


    @Test
    public void test8()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":null }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_NULL, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, true);
    }


    @Test
    public void test9()
    {
        String expected = "KuAUcjF9GTWoR5fsGYOuJD/Gqig=";
        String actual = sha1().update("Hello, world.").digestAsString(new Base64());

        assertEquals(expected, actual);
    }
}
