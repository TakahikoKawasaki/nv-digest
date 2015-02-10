/*
 * Copyright (C) 2013-2015 Neo Visionaries Inc.
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


import static com.neovisionaries.security.Digest.Feature.IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_EMPTY_ARRAY;
import static com.neovisionaries.security.Digest.Feature.IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_EMPTY_OBJECT;
import static com.neovisionaries.security.Digest.Feature.IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_EMPTY_STRING;
import static com.neovisionaries.security.Digest.Feature.IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_FALSE;
import static com.neovisionaries.security.Digest.Feature.IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_NULL;
import static com.neovisionaries.security.Digest.Feature.IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_ZERO;
import static com.neovisionaries.security.Digest.Feature.SORT_JSON_OBJECT_ENTRY_KEYS;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import java.io.IOException;
import java.nio.ByteBuffer;
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


    @Test
    public void test10()
    {
        ByteBuffer byteBuffer = ByteBuffer.allocate(10);
        byteBuffer.put(new byte[] { 1, 2, 3, 4, 5});
        byteBuffer.flip();

        // Ensure there is no infinite loop.
        Digest.getInstanceSHA256().update(
                "Hello, world.",
                new String[] { "Hello", "world" },

                Boolean.TRUE,
                new boolean[] { true, false },
                new Boolean[] { Boolean.TRUE, Boolean.FALSE },

                Byte.valueOf((byte)0),
                new byte[] { (byte)0, (byte)1 },
                new Byte[] { Byte.valueOf((byte)0), Byte.valueOf((byte)1) },
                byteBuffer,

                Character.valueOf('b'),
                new char[] { 'a', 'b' },
                new Character[] { Character.valueOf('a'), Character.valueOf('b') },

                Double.valueOf(0.0),
                new double[] { 0.0, 1.0 },
                new Double[] { Double.valueOf(0.0), Double.valueOf(1.0) },

                Float.valueOf(0.0F),
                new float[] { 0.0F, 1.0F },
                new Float[] { Float.valueOf(0.0F), Float.valueOf(1.0F) },

                Integer.valueOf(1),
                new int[] { 1, 2 },
                new Integer[] { Integer.valueOf(0), Integer.valueOf(1) },

                Long.valueOf(0L),
                new long[] { 0L, 1L },
                new Long[] { Long.valueOf(0L), Long.valueOf(1L) },

                Short.valueOf((short)0),
                new short[] { (short)0, (short)1 },
                new Short[] { Short.valueOf((short)0), Short.valueOf((short)1) },

                new Object[] { new boolean[] { true, false }, new byte[] { (byte)0, (byte)1 } },
                new Object[] {
                    new Object[] { new char[] { 'a', 'b' }, new short[] { 10, 20 } },
                    new Object[] { new float[] { 1.0F, 2.0F }, new double[] { 3.0, 4.0 } }
                }
                );

        assertTrue(true);
    }


    @Test
    public void test11()
    {
        List<Boolean> list = new ArrayList<Boolean>();
        list.add(Boolean.TRUE);
        list.add(Boolean.FALSE);
        list.add(Boolean.TRUE);

        String digest1 = md5().update(list).digestAsString();

        String digest2 = md5()
                .update(true)
                .update(false)
                .update(true)
                .digestAsString();

        String digest3 = md5()
                .update(new boolean[] { true, false, true })
                .digestAsString();

        String digest4 = md5()
                .update(true, false, true)
                .digestAsString();

        assertEquals(digest1, digest2);
        assertEquals(digest1, digest3);
        assertEquals(digest1, digest4);
    }


    @Test
    public void test12()
    {
        List<Character> list = new ArrayList<Character>();
        list.add(Character.valueOf('a'));
        list.add(Character.valueOf('b'));
        list.add(Character.valueOf('c'));

        String digest1 = md5().update(list).digestAsString();

        String digest2 = md5()
                .update('a')
                .update('b')
                .update('c')
                .digestAsString();

        String digest3 = md5()
                .update(new char[] { 'a', 'b', 'c' })
                .digestAsString();

        String digest4 = md5()
                .update('a', 'b', 'c')
                .digestAsString();

        assertEquals(digest1, digest2);
        assertEquals(digest1, digest3);
        assertEquals(digest1, digest4);
    }


    @Test
    public void test13()
    {
        List<Double> list = new ArrayList<Double>();
        list.add(Double.valueOf(0.0));
        list.add(Double.valueOf(1.1));
        list.add(Double.valueOf(2.2));

        String digest1 = md5().update(list).digestAsString();

        String digest2 = md5()
                .update(0.0)
                .update(1.1)
                .update(2.2)
                .digestAsString();

        String digest3 = md5()
                .update(new double[] { 0.0, 1.1, 2.2 })
                .digestAsString();

        String digest4 = md5()
                .update(0.0, 1.1, 2.2)
                .digestAsString();

        assertEquals(digest1, digest2);
        assertEquals(digest1, digest3);
        assertEquals(digest1, digest4);
    }


    @Test
    public void test14()
    {
        List<Float> list = new ArrayList<Float>();
        list.add(Float.valueOf(0.0F));
        list.add(Float.valueOf(1.1F));
        list.add(Float.valueOf(2.2F));

        String digest1 = md5().update(list).digestAsString();

        String digest2 = md5()
                .update(0.0F)
                .update(1.1F)
                .update(2.2F)
                .digestAsString();

        String digest3 = md5()
                .update(new float[] { 0.0F, 1.1F, 2.2F })
                .digestAsString();

        String digest4 = md5()
                .update(0.0F, 1.1F, 2.2F)
                .digestAsString();

        assertEquals(digest1, digest2);
        assertEquals(digest1, digest3);
        assertEquals(digest1, digest4);
    }


    @Test
    public void test15()
    {
        List<Integer> list = new ArrayList<Integer>();
        list.add(Integer.valueOf(100));
        list.add(Integer.valueOf(200));
        list.add(Integer.valueOf(300));

        String digest1 = md5().update(list).digestAsString();

        String digest2 = md5()
                .update(100)
                .update(200)
                .update(300)
                .digestAsString();

        String digest3 = md5()
                .update(new int[] { 100, 200, 300 })
                .digestAsString();

        String digest4 = md5()
                .update(100, 200, 300)
                .digestAsString();

        assertEquals(digest1, digest2);
        assertEquals(digest1, digest3);
        assertEquals(digest1, digest4);
    }


    @Test
    public void test16()
    {
        List<Long> list = new ArrayList<Long>();
        list.add(Long.valueOf(1000L));
        list.add(Long.valueOf(2000L));
        list.add(Long.valueOf(3000L));

        String digest1 = md5().update(list).digestAsString();

        String digest2 = md5()
                .update(1000L)
                .update(2000L)
                .update(3000L)
                .digestAsString();

        String digest3 = md5()
                .update(new long[] { 1000L, 2000L, 3000L })
                .digestAsString();

        String digest4 = md5()
                .update(1000L, 2000L, 3000L)
                .digestAsString();

        assertEquals(digest1, digest2);
        assertEquals(digest1, digest3);
        assertEquals(digest1, digest4);
    }


    @Test
    public void test17()
    {
        List<Short> list = new ArrayList<Short>();
        list.add(Short.valueOf((short)10));
        list.add(Short.valueOf((short)20));
        list.add(Short.valueOf((short)30));

        String digest1 = md5().update(list).digestAsString();

        String digest2 = md5()
                .update((short)10)
                .update((short)20)
                .update((short)30)
                .digestAsString();

        String digest3 = md5()
                .update(new short[] { 10, 20, 30 })
                .digestAsString();

        String digest4 = md5()
                .update((short)10, (short)20, (short)30)
                .digestAsString();

        assertEquals(digest1, digest2);
        assertEquals(digest1, digest3);
        assertEquals(digest1, digest4);
    }


    @Test
    public void test18()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":false }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_FALSE, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, true);
    }


    @Test
    public void test19()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":true }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_FALSE, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, false);
    }


    @Test
    public void test20()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":0, \"key3\":0.0 }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_ZERO, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, true);
    }


    @Test
    public void test21()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":0, \"key3\":1.23 }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_ZERO, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, false);
    }


    @Test
    public void test22()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":\"\" }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_EMPTY_STRING, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, true);
    }


    @Test
    public void test23()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":\"value2\" }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_EMPTY_STRING, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, false);
    }


    @Test
    public void test24()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":[] }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_EMPTY_ARRAY, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, true);
    }


    @Test
    public void test25()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":[ null ] }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_EMPTY_ARRAY, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, false);
    }


    @Test
    public void test26()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":{} }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_EMPTY_OBJECT, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, true);
    }


    @Test
    public void test27()
    {
        String json1 = "{ \"key1\":\"value1\", \"key2\":{ \"key\":null } }";
        String json2 = "{ \"key1\":\"value1\" }";

        Digest digest1 = sha1().setEnabled(IGNORE_JSON_OBJECT_ENTRY_WITH_VALUE_EMPTY_OBJECT, true);
        Digest digest2 = sha1();

        doJsonTest(json1, json2, digest1, digest2, false);
    }
}
