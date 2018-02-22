package de.saly.kafka.crypto;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;

public abstract class SerdeCryptoBase {

    public static final String CRYPTO_PRIVATEKEY_FILEPATH = "crypto.privatekey.filepath";
    public static final String CRYPTO_PUBLICKEY_FILEPATH = "crypto.publickey.filepath";
    public static final String CRYPTO_IGNORE_DECRYPT_FAILURES = "crypto.ignore_decrypt_failures";
    static final byte[] MAGIC_BYTES = new byte[] { (byte) 0xAF, (byte) 0xCB };
    private static final int MAGIC_BYTES_LENGTH = MAGIC_BYTES.length;
    private static final int HEADER_LENGTH = MAGIC_BYTES_LENGTH + 1;
    private static final String KEY_FACTORY = "EC";
    private static final String ASYMMETRIC_TRANFORMATION = "ECIESWITHAES-CBC";
    private int opMode;
    private boolean ignoreDecryptFailures = false;
    private ProducerCryptoBundle producerCryptoBundle = null;
    private ConsumerCryptoBundle consumerCryptoBundle = null;
    private static final int IV_SIZE = 16;
    
    private static final byte[]  d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    private static final byte[]  e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8 };
    
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    //not thread safe
    private class ConsumerCryptoBundle {

        private final Cipher decryptingCipher;
        private final PrivateKey privateKey;
        private final PublicKey publicKey;

        private ConsumerCryptoBundle(PrivateKey privateKey, PublicKey publicKey) throws Exception {     
        	this.privateKey = privateKey;
        	this.publicKey = publicKey;
            decryptingCipher = Cipher.getInstance(ASYMMETRIC_TRANFORMATION, BC);
        }

        private byte[] decrypt(byte[] encrypted) throws KafkaException {
            try {
                if (encrypted[0] == MAGIC_BYTES[0] && encrypted[1] == MAGIC_BYTES[1]) {
                    final byte ivLen = encrypted[2];
                    final int offset = HEADER_LENGTH + ivLen;
                    final byte[] iv = Arrays.copyOfRange(encrypted, HEADER_LENGTH, HEADER_LENGTH + ivLen);
                    final IESParameterSpec param = new IESParameterSpec(d, e, 128, 128, iv);
                    decryptingCipher.init(Cipher.DECRYPT_MODE, new IEKeySpec(privateKey, publicKey), param);
                    return crypt(decryptingCipher, encrypted, offset, encrypted.length - offset);
                } else {
                    return encrypted; //not encrypted, just bypass decryption
                }
            } catch (Exception e) {
                if(ignoreDecryptFailures) {
                    return encrypted; //Probably not encrypted, just bypass decryption
                }
                
                throw new KafkaException("Decrypt failed",e);
            }
        }
    }

    private class ThreadAwareKeyInfo {
        private final Cipher encrypingCipher;
        private final SecureRandom random = new SecureRandom();

        protected ThreadAwareKeyInfo(PublicKey publicKey, PrivateKey privateKey) throws Exception {
            encrypingCipher = Cipher.getInstance(ASYMMETRIC_TRANFORMATION, BC);
        }
    }

    //threads safe
    private class ProducerCryptoBundle {

        private ThreadLocal<ThreadAwareKeyInfo> keyInfo = new ThreadLocal<ThreadAwareKeyInfo>() {
            @Override
            protected ThreadAwareKeyInfo initialValue() {
                try {
                    return new ThreadAwareKeyInfo(publicKey, privateKey);
                } catch (Exception e) {
                    throw new KafkaException(e);
                }
            }
        };
        private final PublicKey publicKey;
        private final PrivateKey privateKey;

        private ProducerCryptoBundle(PublicKey publicKey, PrivateKey privateKey) throws Exception {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", BC);
            ka.init(privateKey);
            ka.doPhase(publicKey, true);

            // Read shared secret
            byte[] sharedSecret = ka.generateSecret();
        }

        private void newKey() throws Exception {
            keyInfo.remove();
        }

        private byte[] encrypt(byte[] plain) throws KafkaException {
            final ThreadAwareKeyInfo ki = keyInfo.get();

            try {
                final byte[] aesIv = new byte[IV_SIZE];
                ki.random.nextBytes(aesIv);
                final IESParameterSpec param = new IESParameterSpec(d, e, 128, 128, aesIv);
                ki.encrypingCipher.init(Cipher.ENCRYPT_MODE, new IEKeySpec(privateKey, publicKey), param);
                return concatenate(MAGIC_BYTES, 
                		new byte[] { (byte) aesIv.length },
                        aesIv, 
                        crypt(ki.encrypingCipher, plain));
            } catch (Exception e) {
                throw new KafkaException(e);
            }
        }
    }

    protected void init(int opMode, Map<String, ?> configs, boolean isKey) throws KafkaException {
        this.opMode = opMode;
        
        final String ignoreDecryptFailuresProperty = (String) configs.get(CRYPTO_IGNORE_DECRYPT_FAILURES);
        
        if(ignoreDecryptFailuresProperty != null && ignoreDecryptFailuresProperty.length() != 0) {
            ignoreDecryptFailures = Boolean.parseBoolean(ignoreDecryptFailuresProperty);
        }
        
        try {
        	String privateKeyFile = (String) configs.get(CRYPTO_PRIVATEKEY_FILEPATH);
        	String publicKeyFile = (String) configs.get(CRYPTO_PUBLICKEY_FILEPATH);
        	
            if (opMode == Cipher.DECRYPT_MODE) {
                //Consumer
                consumerCryptoBundle = new ConsumerCryptoBundle(createPrivateKey(readBytesFromFile(privateKeyFile)),createPublicKey(readBytesFromFile(publicKeyFile)));
            } else {
                //Producer
                producerCryptoBundle = new ProducerCryptoBundle(createPublicKey(readBytesFromFile(publicKeyFile)),createPrivateKey(readBytesFromFile(privateKeyFile)));
            }
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    protected byte[] crypt(byte[] array) throws KafkaException {
        if (array == null || array.length == 0) {
            return array;
        }

        if (opMode == Cipher.DECRYPT_MODE) {
            //Consumer
            return consumerCryptoBundle.decrypt(array);
        } else {
            //Producer
            byte[] e = producerCryptoBundle.encrypt(array);
            return e;
        }
    }

    /**
     * Generate new key for the current thread
     */
    protected void newKey() {
        try {
            producerCryptoBundle.newKey();
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    //Hereafter there are only helper methods

    @SuppressWarnings("unchecked")
    protected <T> T newInstance(Map<String, ?> map, String key, Class<T> klass) throws KafkaException {
        Object val = map.get(key);
        if (val == null) {
            throw new KafkaException("No value for '" + key + "' found");
        } else if (val instanceof String) {
            try {
                return (T) Utils.newInstance(Class.forName((String) val));
            } catch (Exception e) {
                throw new KafkaException(e);
            }
        } else if (val instanceof Class) {
            return (T) Utils.newInstance((Class<T>) val);
        } else {
            throw new KafkaException("Unexpected type '" + val.getClass() + "' for '" + key + "'");
        }
    }

    private static PrivateKey createPrivateKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance(KEY_FACTORY, BC);
        return kf.generatePrivate(spec);
    }

    private static PublicKey createPublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance(KEY_FACTORY, BC);
        return kf.generatePublic(spec);
    }

    private static byte[] readBytesFromFile(String filename) throws IOException {
        if (filename == null) {
            throw new IllegalArgumentException("Filename must not be null");
        }

        File f = new File(filename);
        DataInputStream dis = new DataInputStream(new FileInputStream(f));
        byte[] bytes = new byte[(int) f.length()];
        dis.readFully(bytes);
        dis.close();
        return bytes;
    }

    private static byte[] crypt(Cipher c, byte[] plain) throws IllegalBlockSizeException, BadPaddingException {
        return c.doFinal(plain);
    }

    private static byte[] crypt(Cipher c, byte[] plain, int offset, int len) throws IllegalBlockSizeException, BadPaddingException {
        return c.doFinal(plain, offset, len);
    }

    public static byte[] concatenate(byte[] a, byte[] b, byte[] c, byte[] d) {
        if (a != null && b != null && c != null && d != null) {
            byte[] rv = new byte[a.length + b.length + c.length + d.length];
            System.arraycopy(a, 0, rv, 0, a.length);
            System.arraycopy(b, 0, rv, a.length, b.length);
            System.arraycopy(c, 0, rv, a.length + b.length, c.length);
            System.arraycopy(d, 0, rv, a.length + b.length + c.length, d.length);
            return rv;
        } else {
            throw new IllegalArgumentException("arrays must not be null");
        }
    }
}
