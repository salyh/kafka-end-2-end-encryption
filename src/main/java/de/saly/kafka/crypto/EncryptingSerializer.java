package de.saly.kafka.crypto;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;

import org.apache.kafka.common.serialization.Serializer;

/**
 * 
 * This is a serialization wrapper which adds message encryption. Its intended to be used together with {@link DecryptingDeserializer} 
 * <p>
 * Configuration<p>
 * <ul>
 * <li><em>crypto.rsa.publickey.filepath</em> path on the local filesystem which hold the RSA public key (X.509 format) of the consumer
 * <li><em>crypto.wrapped_serializer</em> is the class or full qualified class name or the wrapped serializer
 * <li><em>crypto.hash_method</em> Type of hash generated for the AES key (optional, default is "SHA-256")
 * <li><em>crypto.new_key_msg_interval</em> Generate new AES every n messages (default is -1, that means never generate a new key)
 * </ul>
 * <p>
 * Each message is encrypted with "AES/CBC/PKCS5Padding" before its sent to Kafka. The AES key as well as the initialization vector are random.
 * The AES key is attached to the message in a RSA encrypted manner. The IV is also attached but not RSA encrypted. There is also a hash value
 * of the AES key to allow consumers caching of decrypted AES keys. Finally we have a few magic and header bytes.
 * The resulting byte array looks therefore like this:
 * <p>
 * <pre>MMLLLHH..HHEEEE..EEEEIIII..IIIOOOOO....OOOOOO</pre>
 * <p>
 * <ul>
 * <li> MM: Two magic bytes 0xDF 0xBB to detect if this byte sequence is encrypted or not
 * <li> LLL: Three bytes indicating the length of the AES key hash, the RSA encrypted AES key and the IV
 * <li> HH..HH: AES key hash
 * <li> EE..EE: RSA encrypted AES key
 * <li> II..II: Initialization vector (if any)
 * <li> OO..OO: The AES encrypted original message
 * </ul>
 * <p>
 * <em>MMLLL</em> is called the encryption header and consists of 5 bytes.
 * <p>
 * <ul>
 * <li> M1: 0xDF
 * <li> M2: 0xBB
 * <li> L1: length of the AES key hash
 * <li> L2: RSA factor f so that f*128*8 evaluates to the RSA keysize (in bits)
 * <li> L3: length of the initialization vector in bytes (always 16 for AES CBC)
 * </ul>
 * <p>
 * RSA public/private keypair can be generated with<br>
 * <em>java -cp kafka-end-2-end-encryption-1.0.0.jar de.saly.kafka.crypto.RsaKeyGen 2048</em>
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
