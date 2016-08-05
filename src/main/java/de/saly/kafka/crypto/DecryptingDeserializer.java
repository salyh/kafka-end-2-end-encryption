package de.saly.kafka.crypto;

import java.util.Map;

import javax.crypto.Cipher;

import org.apache.kafka.common.serialization.Deserializer;

/**
 * This is a deserialization (for the Consumer) wrapper which adds transparent end-to-end message encryption. 
 * Its intended to be used together with {@link EncryptingSerializer}
 * <p>
 * Configuration<p>
 * <ul>
 * <li><em>crypto.rsa.privatekey.filepath</em> path on the local filesystem which hold the RSA private key (PKCS#8 format) of the consumer
 * <li><em>crypto.wrapped_deserializer</em> is the class or full qualified class name or the wrapped deserializer
 * <li><em>crypto.ignore_decrypt_failures</em> Skip message decryption on error and just pass the byte[] unencrypted (optional, default is "false"). Possible values are "true" or "false".
 * </ul>
 * 
 * See {@link EncryptingSerializer} on how encryption works
 * 
 * This class will auto detect if an incoming message is encrypted. If not then no decryption attempt is made and message gets handled normally.
 * <p>
 * <b>Note</b>: As Consumers are not multithreading-safe this deserializer is also not thread-safe
 * <p>
 * @param <T> The type to be deserialized from (applied to the wrapped deserializer)
 */
public class DecryptingDeserializer<T> extends SerdeCryptoBase implements Deserializer<T> {

    public static final String CRYPTO_VALUE_DESERIALIZER = "crypto.wrapped_deserializer";
    private Deserializer<T> inner;

    @SuppressWarnings("unchecked")
    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        inner = newInstance(configs, CRYPTO_VALUE_DESERIALIZER, Deserializer.class);
        inner.configure(configs, isKey);
        init(Cipher.DECRYPT_MODE, configs, isKey);
    }

    @Override
    public T deserialize(String topic, byte[] data) {
        return inner.deserialize(topic, crypt(data));
    }

    @Override
    public void close() {
        if (inner != null) {
            inner.close();
        }
    }
}
