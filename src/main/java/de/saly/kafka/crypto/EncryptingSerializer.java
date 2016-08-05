package de.saly.kafka.crypto;

import java.util.Map;

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
 * </ul>
 * 
 * Each message is encrypted with "AES/CBC/PKCS5Padding" before its sent to Kafka. The AES key as well as the initialization vector are random.
 * The AES key is attached to the message in a RSA encrypted manner. The IV is also attached but not RSA encrypted. There is also a hash value
 * of the AES key to allow consumers caching of decrypted AES keys. Finally we have a few magic and header bytes.
 * The resulting byte array looks therefore like this:
 * 
 * <pre>MMLLLHH..HHEEEE..EEEEIIII..IIIOOOOO....OOOOOO</pre>
 * 
 * <ul>
 * <li> MM: Two magic bytes 0xDF 0xBB to detect if this byte sequence is encrypted or not
 * <li> LLL: Three bytes indicating the length of the AES key hash, the RSA encrypted AES key, the IV
 * <li> HH..HH: AES key hash
 * <li> EE..EE: RSA encrypted AES key
 * <li> II..II: Initialization vector
 * <li> OO..OO: The AES encrypted original message
 * </ul>
 * 
 * <em>MMLLL</em> is called the encryption header and consists of 5 bytes.
 * 
 * <ul>
 * <li> M1: 0xDF
 * <li> M2: 0xBB
 * <li> L1: length of the AES key hash
 * <li> L2: RSA factor f so that f*128*8 evaluates to the RSA keysize (in bits)
 * <li> L3: length of the initialization vector in bytes (always 16 for AES CBC)
 * </ul>
 * 
 * RSA public/private keypair can be generated with<br>
 * <em>java org.apache.kafka.common.serialization.RsaKeyGen &lt;keysize in bits&gt;</em>
 * 
 * <p>
 * <b>Note</b>: As Producers are multithreading-safe this serializer is also thread-safe
 * <p>
 * 
 * @param <T> The type to be serialized from (applied to the wrapped serializer)
 */
public class EncryptingSerializer<T> extends SerdeCryptoBase implements Serializer<T> {

    public static final String CRYPTO_VALUE_SERIALIZER = "crypto.wrapped_serializer";
    private Serializer<T> inner;

    @SuppressWarnings("unchecked")
    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        inner = newInstance(configs, CRYPTO_VALUE_SERIALIZER, Serializer.class);
        inner.configure(configs, isKey);
        init(Cipher.ENCRYPT_MODE, configs, isKey);
    }

    @Override
    public byte[] serialize(String topic, T data) {
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
