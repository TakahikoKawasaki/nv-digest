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


Javadoc
-------

[nv-digest javadoc](http://TakahikoKawasaki.github.com/nv-digest/)



Example
-------

    String digest = Digest.getInstanceSHA1()
                    .update("Hello, world.")
		    .digestAsString();

    // digest holds "2ae01472317d1935a84797ec1983ae243fc6aa28".


Maven
-----

    <dependency>
        <groupId>com.neovisionaries</groupId>
        <artifactId>nv-digest</artifactId>
        <version>1.0</version>
    </dependency>


Author
------

Takahiko Kawasaki, Neo Visionaries Inc.
