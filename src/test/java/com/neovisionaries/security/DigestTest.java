/*
 * Copyright (C) 2013 Neo Visionaries Inc.
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


import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;


public class DigestTest
{
    @Test
    public void test1()
    {
        String expected = "2ae01472317d1935a84797ec1983ae243fc6aa28";
        String actual = Digest.getInstanceSHA1().update("Hello, world.").digestAsString();

        assertEquals(expected, actual);
    }


    @Test
    public void test2()
    {
        List<Number> list = new ArrayList<Number>();
        list.add(new Byte((byte)1));
        list.add(new Short((short)2));
        list.add(new Integer((int)3));
        list.add(new Long((long)4));
        list.add(new Float((float)5));
        list.add(new Double((double)6));

        String digest1 = Digest.getInstanceSHA1().update(list).digestAsString();

        String digest2 = Digest.getInstanceSHA1()
                         .update((byte)1)
                         .update((short)2)
                         .update((int)3)
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

        String digest1 = Digest.getInstanceMD5().update(list).digestAsString();

        String digest2 = Digest.getInstanceMD5()
                         .update("Apple")
                         .update("Banana")
                         .update("Cherry")
                         .digestAsString();

        assertEquals(digest1, digest2);
    }
}
