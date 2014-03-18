nv-digest
=========

Overview
--------

Message digest utility based on `java.security.MessageDigest`.

`Digest` class is a wraper class over `MessageDigest` and provides
many `update` methods in a fluent style, meaning `update` methods
can be chained. They are provided for all the primitive types and
`String`, and their array types. In addition, `updateJson(String)`
has been available since the version 1.2 which updates the digest
with the content of the given JSON.

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

```java
// Compute SHA-1 of "Hello, world.".
// 'digest' will have "2ae01472317d1935a84797ec1983ae243fc6aa28".
String digest = Digest.getInstanceSHA1()
                .update("Hello, world.")
                .digestAsString();

// Compute SHA-1 of "Hello, world." and ge the result as Base64.
// 'digest' will have "KuAUcjF9GTWoR5fsGYOuJD/Gqig=".
String digest = Digest.getInstanceSHA1()
                .update("Hello, world.")
                .digestAsString(new Base64());


// Compute SHA-1 of two JSONs.
// 'result1' and 'result2' will have the same value.
String json1 = "{ \"key1\":\"value1\", \"key2\":\"value2\" }";
String json2 = "{ \"key2\":\"value2\", \"key1\":\"value1\" }";
String result1 = Digest.getInstanceSHA1().updateJson(json1).digestAsString();
String result2 = Digest.getInstanceSHA1().updateJson(json2).digestAsString();
```


Maven
-----

```xml
<dependency>
    <groupId>com.neovisionaries</groupId>
    <artifactId>nv-digest</artifactId>
    <version>1.4</version>
</dependency>
```


Author
------

Takahiko Kawasaki, Neo Visionaries Inc.
