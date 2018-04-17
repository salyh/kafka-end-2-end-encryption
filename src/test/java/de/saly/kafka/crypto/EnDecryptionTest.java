package de.saly.kafka.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
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
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
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
        pubKey = File.createTempFile("kafka", "cryptoec");
        pubKey.deleteOnExit();
        privKey = File.createTempFile("kafka", "cryptoec");
        privKey.deleteOnExit();
        
        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ECParameterSpec ecSpec=new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", new BouncyCastleProvider());
        keyGen.initialize(ecSpec, new SecureRandom());
        KeyPair pair = keyGen.genKeyPair();
        publicKey = pair.getPublic().getEncoded();
        privateKey = pair.getPrivate().getEncoded();

        FileOutputStream fout = new FileOutputStream(pubKey);
        fout.write(publicKey);
        fout.close();

        fout = new FileOutputStream(privKey);
        fout.write(privateKey);
        fout.close();
    }

    @Test
    public void testBasicStandard() throws Exception {
        testBasic(128, -1);
    }

    @Test
    public void testAes256() throws Exception {
        Assume.assumeTrue(Cipher.getMaxAllowedKeyLength("AES") >= 256);
        testBasic(256, -1);
    }
    
    @Test(expected = KafkaException.class)
    public void testAesInvalidKeySize() throws Exception {
        Assume.assumeTrue(Cipher.getMaxAllowedKeyLength("AES") >= 256);
        testBasic(111, -1);
    }

    @Test
    public void testAes192() throws Exception {
        Assume.assumeTrue(Cipher.getMaxAllowedKeyLength("AES") >= 192);
        testBasic(192, -1);
    }

    @Test
    public void testBasicInterval1() throws Exception {
        testBasic(128, 1);
    }
    
    @Test
    public void testBasicInterval10() throws Exception {
        testBasic(128, 10);
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
    public void testMultithreadedInterval1000() throws Exception {
        testMultithreadedBasic(1000);
    }
    
    protected void testMultithreadedBasic(int msgInterval) throws Exception {
        final String str = "The quick brown fox jumps over the lazy dog";

        final Map<String, Object> config = new HashMap<String, Object>();
        config.put(SerdeCryptoBase.CRYPTO_PRIVATEKEY_FILEPATH, privKey.getAbsolutePath());
        config.put(SerdeCryptoBase.CRYPTO_PUBLICKEY_FILEPATH, pubKey.getAbsolutePath());
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
                        final Deserializer<String> deserializer = new DecryptingDeserializer<String>();
                        deserializer.configure(config, false);
                        for(int i=0; i<1000; i++) {
                            final byte[] enc = serializer.serialize(TOPIC, str+i+Thread.currentThread().getName());
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

    protected void testBasic(int keylen, int msgInterval) throws Exception {

        final Map<String, Object> serializerConfig = new HashMap<String, Object>();
        serializerConfig.put(SerdeCryptoBase.CRYPTO_PRIVATEKEY_FILEPATH, privKey.getAbsolutePath());
        serializerConfig.put(SerdeCryptoBase.CRYPTO_PUBLICKEY_FILEPATH, pubKey.getAbsolutePath());
        serializerConfig.put(SerdeCryptoBase.CRYPTO_AES_KEY_LEN, String.valueOf(keylen));
        serializerConfig.put(EncryptingSerializer.CRYPTO_VALUE_SERIALIZER, ByteArraySerializer.class.getName());
        serializerConfig.put(EncryptingSerializer.CRYPTO_NEW_KEY_MSG_INTERVAL, String.valueOf(msgInterval));

        final EncryptingSerializer<byte[]> serializer = new EncryptingSerializer<byte[]>();
        serializer.configure(serializerConfig, false);

        final Map<String, Object> deserializerConfig = new HashMap<String, Object>();
        deserializerConfig.put(SerdeCryptoBase.CRYPTO_PRIVATEKEY_FILEPATH, privKey.getAbsolutePath());
        deserializerConfig.put(SerdeCryptoBase.CRYPTO_PUBLICKEY_FILEPATH, pubKey.getAbsolutePath());
        deserializerConfig.put(SerdeCryptoBase.CRYPTO_AES_KEY_LEN, String.valueOf(keylen));
        deserializerConfig.put(DecryptingDeserializer.CRYPTO_VALUE_DESERIALIZER, ByteArrayDeserializer.class);
        deserializerConfig.put(DecryptingDeserializer.CRYPTO_IGNORE_DECRYPT_FAILURES, "false");
        
        final Deserializer<byte[]> deserializer = new DecryptingDeserializer<byte[]>();
        deserializer.configure(deserializerConfig, false);

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

        deserializerConfig.put(DecryptingDeserializer.CRYPTO_IGNORE_DECRYPT_FAILURES, "true");
        deserializer.configure(deserializerConfig, false);

        try {
            assertArrayEquals(SerdeCryptoBase.MAGIC_BYTES, deserializer.deserialize(TOPIC, SerdeCryptoBase.MAGIC_BYTES));
        } catch (Exception e) {
            Assert.fail(e.toString());
        }
    }
}
