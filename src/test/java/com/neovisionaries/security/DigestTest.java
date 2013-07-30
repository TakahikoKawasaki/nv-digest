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
}
