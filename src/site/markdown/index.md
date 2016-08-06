# Kafka End2End encryption

A small library with no external dependencies which provide transparent AES end-to-end encryption for Apache Kafka.

## Prerequisites

* Kafka client 0.8.2.0 or higher
* Java 6 or higher (Java 8 **stongly** recommended)
* For AES 256 en-/decryption you have to install [JCE Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/overview/index.html)

## Features

* Transparent encryption, will be configured as serializer/deserializer
* End-to-end encryption of Kafka messages with random AES key(s)
* AES key is attached in RSA encrypted form to every message
* Consumer detects if a message is encrypted and can therefore handle also unencrypted messages
* No external dependencies
* On modern hardware with recent Java installed AES will be computed directly on the CPU (via AES-NI) 

## Get it

### via Maven
    <dependency>
      <groupId>de.saly</groupId>
      <artifactId>kafka-end-2-end-encryption</artifactId>
      <version>1.0.1</version>
    <dependency>
    
### or download .jar file

   [Here](http://search.maven.org/#search%7Cga%7C1%7Ckafka-end-2-end-encryption)

### or build it yourself

    mvn package

Include the library in the classpath of the producer or consumer.

## Configuration

This library provide a serializer and a deserializer which handles the encryption/decryption stuff and delegate the message then to an underlying serializer/deserializer.
In other words: Your original serializer/deserializer will be wrapped with that one.

### Producer

    crypto.wrapped_serializer: <wrapped serializer> #mandatory
    crypto.rsa.publickey.filepath: <path> #mandatory
    crypto.aes.key_len: 128 #optional
    crypto.hash_method: SHA-256 #optional
    
### Consumer

    crypto.wrapped_deserializer: <wrapped deserializer> #mandatory
    crypto.rsa.privatekey.filepath: <path> #mandatory
    #If set to true then the original message will be returned on decrypt failure
    #If set to false (the default) an exception will be thrown on decrypt failure
    crypto.ignore_decrypt_failures: false #optional

## Create a RSA key pair

    java -cp kafka-end-2-end-encryption-1.0.0.jar de.saly.kafka.crypto.RsaKeyGen 2048

This creates a 2048-bit RSA key pair. The publickey is used on the consumer side to encrypt the AES key attached to every message.
The privatekey is used on the consumer side to decrypt the AES key.

## Example

### Producer

    value.serializer: de.saly.kafka.crypto.EncryptingSerializer
    crypto.wrapped_serializer: org.apache.kafka.common.serialization.StringSerializer
    crypto.rsa.publickey.filepath: /opt/rsa_publickey_2048_db484e3c-c3f5-4197-bb40-2f60c498b157
    
### Consumer

    value.deserializer: de.saly.kafka.crypto.DecryptingDeserializer
    crypto.wrapped_deserializer: org.apache.kafka.common.serialization.StringDeserializer
    crypto.rsa.privatekey.filepath: /opt/rsa_privatekey_2048_db484e3c-c3f5-4197-bb40-2f60c498b157
    
If you want also encrypt the key of the message use "key.serializer" and "key.deserializer" the same way.

## Limitations

Currently value and key wrapped serializer cannot be different.
