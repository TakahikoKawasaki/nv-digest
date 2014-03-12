nv-digest
=========

Overview
--------

Message digest utility based on `java.security.MessageDigest`.

`Digest` class is a wraper class over `MessageDigest` and provides
many `update` methods in a fluent style, meaning `update` methods
can be chained. They are provided for all the primitive types and
`String`, and their array types.

`getInstanceXXX` methods (where `XXX` is a pre-defined algorithm
name with hyphens removed) such as `getInstanceSHA1()` are
provided. They won't throw `NoSuchAlgorithmException`.


License
-------

Apache License, Version 2.0


Download
--------

    git clone https://github.com/TakahikoKawasaki/nv-digest.git


JavaDoc
-------

[nv-digest JavaDoc](http://TakahikoKawasaki.github.com/nv-digest/)



Example
-------

    String digest = Digest.getInstanceSHA1()
                    .update("Hello, world.")
                    .digestAsString();

    // digest holds "2ae01472317d1935a84797ec1983ae243fc6aa28".

    String json1 = "{ \"key1\":\"value1\", \"key2\":\"value2\" }";
    String json2 = "{ \"key2\":\"value2\", \"key1\":\"value1\" }";
    String result1 = Digest.getInstanceSHA1().updateJson(json1).digestAsString();
    String result2 = Digest.getInstanceSHA1().updateJson(json2).digestAsString();

    // result1 and result2 have the same value.


Maven
-----

    <dependency>
        <groupId>com.neovisionaries</groupId>
        <artifactId>nv-digest</artifactId>
        <version>1.2</version>
    </dependency>


Author
------

Takahiko Kawasaki, Neo Visionaries Inc.
