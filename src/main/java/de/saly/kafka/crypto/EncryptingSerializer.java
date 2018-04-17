package de.saly.kafka.crypto;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;

import org.apache.kafka.common.serialization.Serializer;

/**
 * 
 * This is a serialization wrapper which adds message encryption. Its intended to be used together with {@link DecryptingDeserializer} 
 * Use it for producers.
 * <p>
 * Configuration<p>
 * <ul>
 * <li><em>crypto.publickey.filepath</em> path on the local filesystem which hold the EC public key of the consumer
 * <li><em>crypto.privatekey.filepath</em> path on the local filesystem which hold the EC private key of the producer
 * <li><em>crypto.wrapped_serializer</em> is the class or full qualified class name or the wrapped serializer
 * <li><em>crypto.new_key_msg_interval</em> Generate new AES every n messages (default is -1, that means never generate a new key)
 * </ul>
 * <p>
 * Each message is encrypted with AES (with a random IV) in GCM mode before its sent to Kafka.
 * In addition to the encrypted message we add two magic bytes, the IV length as another byte and the IV itself (by default 12 bytes).
 * That means we add a constant "overhead" of 15 bytes per message.
 * The resulting byte array looks therefore like this:
 * <p>
 * <pre>MMLIIII..IIIOOOOO....OOOOOO</pre>
 * <p>
 * <ul>
 * <li> MM: Two magic bytes 0xDF 0xBB to detect if this byte sequence is encrypted or not
 * <li> L: One byte indicating the length of the IV
 * <li> II..II: Initialization vector
 * <li> OO..OO: The AES encrypted original message
 * </ul>
 * <p>
 * <em>MML</em> is called the encryption header and consists of 3 bytes.
 * <p>
 * <ul>
 * <li> M1: 0xBD
 * <li> M2: 0xDD
 * <li> L1: length of the initialization vector in bytes
 * </ul>
 * <p>
 * EC public/private keypair can be generated with<br>
 * <em>java -cp kafka-end-2-end-encryption-1.0.0.jar de.saly.kafka.crypto.ECKeyGen</em>
 * <p>
 * You will need to generate two keypairs - one for the producer and one for the consumer.
 * To make the Diffie–Hellman work the producer needs to be configure with its private key and the public key of the consumer.
 * The consumer needs to be configued with its private key and the public of the consumer.
 * <p>
 * <b>Note</b>: As Producers are multithreading-safe this serializer is also thread-safe
 * <p>
 * 
 * @param <T> The type to be serialized from (applied to the wrapped serializer)
 */
public class EncryptingSerializer<T> extends SerdeCryptoBase implements Serializer<T> {

    public static final String CRYPTO_VALUE_SERIALIZER = "crypto.wrapped_serializer";
    public static final String CRYPTO_NEW_KEY_MSG_INTERVAL = "crypto.new_key_msg_interval";
    public int msgInterval = -1;
    private Serializer<T> inner;
    private final AtomicInteger msg = new AtomicInteger();

    @SuppressWarnings("unchecked")
    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        inner = newInstance(configs, CRYPTO_VALUE_SERIALIZER, Serializer.class);
        inner.configure(configs, isKey);
        init(Cipher.ENCRYPT_MODE, configs, isKey);
        String msgIntervalProperty = (String) configs.get(CRYPTO_NEW_KEY_MSG_INTERVAL);
        if (msgIntervalProperty != null && msgIntervalProperty.length() > 0) {
            msgInterval = Integer.parseInt(msgIntervalProperty);
            if (msgInterval < 1) {
                msgInterval = -1;
            }
        }
    }

    @Override
    public byte[] serialize(String topic, T data) {
        if (msgInterval > 0 && msg.compareAndSet(msgInterval, 0)) {
            newKey();
        } else if (msgInterval > 0) {
            msg.incrementAndGet();
        }

        return crypt(inner.serialize(topic, data));
    }

    @Override
    public void close() {
        if (inner != null) {
            inner.close();
        }
    }
    
    /**
     * Generate new AES key for the current thread
     */
    public void newKey() {
        super.newKey();
    }
}
