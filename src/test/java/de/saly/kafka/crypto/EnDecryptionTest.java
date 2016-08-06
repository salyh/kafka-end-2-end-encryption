package de.saly.kafka.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.crypto.Cipher;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

public class EnDecryptionTest {

    private final static String TOPIC = "cryptedTestTopic";
    private final File pubKey;
    private final File privKey;
    private final byte[] publicKey;
    private final byte[] privateKey;

    public EnDecryptionTest() throws Exception {
        pubKey = File.createTempFile("kafka", "crypto");
        pubKey.deleteOnExit();
        privKey = File.createTempFile("kafka", "crypto");
        privKey.deleteOnExit();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.genKeyPair();
        publicKey = pair.getPublic().getEncoded();
        privateKey = pair.getPrivate().getEncoded();

        //System.out.println("private key format: "+pair.getPrivate().getFormat()); // PKCS#8
        //System.out.println("public key format: "+pair.getPublic().getFormat()); // X.509

        FileOutputStream fout = new FileOutputStream(pubKey);
        fout.write(publicKey);
        fout.close();

        fout = new FileOutputStream(privKey);
        fout.write(privateKey);
        fout.close();
    }

    @Test
    public void testBasicStandard() throws Exception {
        testBasic("", 128, -1);
    }

    @Test
    public void testAes256() throws Exception {
        Assume.assumeTrue(Cipher.getMaxAllowedKeyLength("AES") >= 256);
        testBasic("", 256, -1);
    }

    @Test
    public void testSHA1() throws Exception {
        testBasic("SHA1", 128, -1);
    }

    @Test
    public void testSHA1_192() throws Exception {
        Assume.assumeTrue(Cipher.getMaxAllowedKeyLength("AES") >= 192);
        testBasic("SHA1", 192, -1);
    }

    @Test
    public void testMD5_192() throws Exception {
        Assume.assumeTrue(Cipher.getMaxAllowedKeyLength("AES") >= 192);
        testBasic("MD5", 192, -1);
    }
    
    @Test
    public void testMSHA512_128() throws Exception {
        testBasic("SHA-512", 128, -1);
    }

    @Test(expected = KafkaException.class)
    public void testInvalidKeySize() throws Exception {
        testBasic("SHA1", 177, -1);
    }

    @Test(expected = KafkaException.class)
    public void testInvalidHashAlgo() throws Exception {
        testBasic("xxx", 128, -1);
    }

    @Test
    public void testBasicInterval1() throws Exception {
        testBasic("", 128, 1);
    }
    
    @Test
    public void testBasicInterval10() throws Exception {
        testBasic("", 128, 10);
    }
    
    @Test
    public void testMultithreadedStandard() throws Exception {
        testMultithreadedBasic(-1);
    }
    
    @Test
    public void testMultithreadedInterval1() throws Exception {
        testMultithreadedBasic(1);
    }
    
    @Test
    public void testMultithreadedInterval10() throws Exception {
        testMultithreadedBasic(10);
    }
    
    protected void testMultithreadedBasic(int msgInterval) throws Exception {
        final String str = "The quick brown fox jumps over the lazy dog";

        final Map<String, Object> config = new HashMap<String, Object>();
        config.put(SerdeCryptoBase.CRYPTO_RSA_PRIVATEKEY_FILEPATH, privKey.getAbsolutePath());
        config.put(SerdeCryptoBase.CRYPTO_RSA_PUBLICKEY_FILEPATH, pubKey.getAbsolutePath());
        config.put(EncryptingSerializer.CRYPTO_VALUE_SERIALIZER, StringSerializer.class.getName());
        config.put(DecryptingDeserializer.CRYPTO_VALUE_DESERIALIZER, StringDeserializer.class);
        config.put(EncryptingSerializer.CRYPTO_NEW_KEY_MSG_INTERVAL, String.valueOf(msgInterval));

        final EncryptingSerializer<String> serializer = new EncryptingSerializer<String>();
        serializer.configure(config, false);
        
        final int threadCount = 200;

        final ExecutorService es = Executors.newFixedThreadPool(threadCount);
        final List<Future<Exception>> futures = new ArrayList<Future<Exception>>();

        for (int i = 0; i < threadCount; i++) {
            Future<Exception> f = es.submit(new Callable<Exception>() {

                @Override
                public Exception call() throws Exception {
                    try {
                        for(int i=0; i<1000; i++) {
                            final byte[] enc = serializer.serialize(TOPIC, str+i+Thread.currentThread().getName());
                            final Deserializer<String> deserializer = new DecryptingDeserializer<String>();
                            deserializer.configure(config, false);
                            assertEquals(str+i+Thread.currentThread().getName(), deserializer.deserialize(TOPIC, enc));
                        }
                        return null;
                    } catch (Exception e) {
                        return e;
                    }

                }

            });
            futures.add(f);
        }

        for (Future<Exception> f : futures) {
            try {
                Exception e = f.get();
                if (e != null) {
                    throw e;
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw e;
            }
        }
    }

    protected void testBasic(String hashMethod, int keylen, int msgInterval) throws Exception {

        final Map<String, Object> config = new HashMap<String, Object>();
        config.put(SerdeCryptoBase.CRYPTO_RSA_PRIVATEKEY_FILEPATH, privKey.getAbsolutePath());
        config.put(SerdeCryptoBase.CRYPTO_RSA_PUBLICKEY_FILEPATH, pubKey.getAbsolutePath());
        config.put(EncryptingSerializer.CRYPTO_VALUE_SERIALIZER, ByteArraySerializer.class.getName());
        config.put(DecryptingDeserializer.CRYPTO_VALUE_DESERIALIZER, ByteArrayDeserializer.class);
        config.put(DecryptingDeserializer.CRYPTO_HASH_METHOD, hashMethod);
        config.put(DecryptingDeserializer.CRYPTO_AES_KEY_LEN, String.valueOf(keylen));
        config.put(DecryptingDeserializer.CRYPTO_IGNORE_DECRYPT_FAILURES, "false");
        config.put(EncryptingSerializer.CRYPTO_NEW_KEY_MSG_INTERVAL, String.valueOf(msgInterval));

        final EncryptingSerializer<byte[]> serializer = new EncryptingSerializer<byte[]>();
        serializer.configure(config, false);

        final Deserializer<byte[]> deserializer = new DecryptingDeserializer<byte[]>();
        deserializer.configure(config, false);

        final Random rand = new Random(System.currentTimeMillis());
        for (int i = 0; i < 1000; i++) {
            final byte[] b = new byte[i];
            rand.nextBytes(b);
            Assert.assertArrayEquals(b, deserializer.deserialize(TOPIC, serializer.serialize(TOPIC, b)));
        }

        for (byte i = 0; i < Byte.MAX_VALUE; i++) {
            final byte[] b = new byte[i];
            Arrays.fill(b, i);
            Assert.assertArrayEquals(b, deserializer.deserialize(TOPIC, serializer.serialize(TOPIC, b)));
        }

        serializer.newKey();

        for (int i = 0; i < 100; i++) {
            final byte[] b = new byte[i];
            rand.nextBytes(b);
            Assert.assertArrayEquals(b, deserializer.deserialize(TOPIC, serializer.serialize(TOPIC, b)));
        }
        byte[] plainText = "The quick brown fox jumps over the lazy dog".getBytes("UTF-8");
        byte[] encryptedText = serializer.serialize(TOPIC, plainText);
        assertArrayEquals(SerdeCryptoBase.MAGIC_BYTES, Arrays.copyOfRange(encryptedText, 0, 2));

        assertArrayEquals(plainText, deserializer.deserialize(TOPIC, plainText));

        try {
            deserializer.deserialize(TOPIC, SerdeCryptoBase.MAGIC_BYTES);
            Assert.fail();
        } catch (Exception e) {
            //expected
        }

        config.put(DecryptingDeserializer.CRYPTO_IGNORE_DECRYPT_FAILURES, "true");
        deserializer.configure(config, false);

        try {
            assertArrayEquals(SerdeCryptoBase.MAGIC_BYTES, deserializer.deserialize(TOPIC, SerdeCryptoBase.MAGIC_BYTES));
        } catch (Exception e) {
            Assert.fail(e.toString());
        }
    }
}
