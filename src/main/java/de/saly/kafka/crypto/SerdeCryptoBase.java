package de.saly.kafka.crypto;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.utils.Utils;
import org.bouncycastle.jcajce.provider.asymmetric.EC;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;

public abstract class SerdeCryptoBase {

    public static final String CRYPTO_RSA_PRIVATEKEY_FILEPATH = "crypto.rsa.privatekey.filepath"; //consumer
    public static final String CRYPTO_RSA_PUBLICKEY_FILEPATH = "crypto.rsa.publickey.filepath"; //producer
    public static final String CRYPTO_HASH_METHOD = "crypto.hash_method";
    public static final String CRYPTO_IGNORE_DECRYPT_FAILURES = "crypto.ignore_decrypt_failures";
    public static final String CRYPTO_AES_KEY_LEN = "crypto.aes.key_len";
    static final byte[] MAGIC_BYTES = new byte[] { (byte) 0xDF, (byte) 0xBB };
    protected static final String DEFAULT_TRANSFORMATION = "AES/GCM/PKCS5Padding";
    private static final Map<String, byte[]> aesKeyCache = new HashMap<String, byte[]>();
    private static final int MAGIC_BYTES_LENGTH = MAGIC_BYTES.length;
    private static final int HEADER_LENGTH = MAGIC_BYTES_LENGTH + 3;
    private static final String AES = "AES";
    private static final String KEY_FACTORY = "EC";
    private static final String ASYMMETRIC_TRANFORMATION = "ECIESWITHAES-CBC";///OAEPWithSHA-256AndMGF1Padding";
    private static final int RSA_MULTIPLICATOR = 2;
    private int opMode;
    private String hashMethod = "SHA-256";
    private int aesKeyLen = 128;
    private boolean ignoreDecryptFailures = false;
    private ProducerCryptoBundle producerCryptoBundle = null;
    private ConsumerCryptoBundle consumerCryptoBundle = null;
    private static final int IV_SIZE = 16;
    private static final int GCM_TAG_BIT_LENGTH = 128 ;
    private static final byte[] AAD_BYTES = "random".getBytes();
    
    byte[]  d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8,1, 2, 3, 4, 5, 6, 7, 8 };
    byte[]  e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1,1, 2, 3, 4, 5, 6, 7, 8 };
    IESParameterSpec param = new IESParameterSpec(d, e, 128, 128, d);
    
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    //not thread safe
    private class ConsumerCryptoBundle {

        private Cipher rsaDecrypt;
        final Cipher aesDecrypt = Cipher.getInstance(DEFAULT_TRANSFORMATION);

        private ConsumerCryptoBundle(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        	System.out.println(privateKey.getClass());
            rsaDecrypt = Cipher.getInstance(ASYMMETRIC_TRANFORMATION, BC);
            rsaDecrypt.init(Cipher.DECRYPT_MODE, new IEKeySpec(privateKey, publicKey), param);
        }

        private byte[] aesDecrypt(byte[] encrypted) throws KafkaException {
            try {
                if (encrypted[0] == MAGIC_BYTES[0] && encrypted[1] == MAGIC_BYTES[1]) {
                    final byte hashLen = encrypted[2];
                    final byte rsaFactor = encrypted[3];
                    final byte ivLen = encrypted[4];
                    final int offset = HEADER_LENGTH + hashLen + (rsaFactor * RSA_MULTIPLICATOR) + ivLen;
                    final String aesHash = DatatypeConverter.printHexBinary(Arrays.copyOfRange(encrypted, HEADER_LENGTH, HEADER_LENGTH + hashLen));
                    final byte[] iv = Arrays.copyOfRange(encrypted, HEADER_LENGTH + hashLen + (rsaFactor * RSA_MULTIPLICATOR),
                            HEADER_LENGTH + hashLen + (rsaFactor * RSA_MULTIPLICATOR) + ivLen);

                    byte[] aesKey;

                    if ((aesKey = aesKeyCache.get(aesHash)) != null) {
                        aesDecrypt.init(Cipher.DECRYPT_MODE, createAESSecretKey(aesKey), new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv), new SecureRandom());
                        aesDecrypt.updateAAD(AAD_BYTES);
                        return crypt(aesDecrypt, encrypted, offset, encrypted.length - offset);
                    } else {
                        byte[] rsaEncryptedAesKey = Arrays.copyOfRange(encrypted, HEADER_LENGTH + hashLen,
                                HEADER_LENGTH + hashLen + (rsaFactor * RSA_MULTIPLICATOR));
                        aesKey = crypt(rsaDecrypt, rsaEncryptedAesKey);
                        aesDecrypt.init(Cipher.DECRYPT_MODE, createAESSecretKey(aesKey), new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv), new SecureRandom());
                        aesDecrypt.updateAAD(AAD_BYTES);
                        aesKeyCache.put(aesHash, aesKey);
                        return crypt(aesDecrypt, encrypted, offset, encrypted.length - offset);
                    }
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
        private final SecretKey aesKey;
        private final byte[] aesHash;
        private final byte[] rsaEncyptedAesKey;
        private final Cipher rsaCipher;
        private final Cipher aesCipher;
        private final SecureRandom random = new SecureRandom();

        protected ThreadAwareKeyInfo(PublicKey publicKey, PrivateKey privateKey) throws Exception {
            byte[] aesKeyBytes = new byte[aesKeyLen/8];
            random.nextBytes(aesKeyBytes);
            aesCipher = Cipher.getInstance(DEFAULT_TRANSFORMATION);
            aesKey = createAESSecretKey(aesKeyBytes);
            aesHash = hash(aesKeyBytes);
            rsaCipher = Cipher.getInstance(ASYMMETRIC_TRANFORMATION, BC);
            rsaCipher.init(Cipher.ENCRYPT_MODE, new IEKeySpec(privateKey, publicKey), param);
            rsaEncyptedAesKey = crypt(rsaCipher, aesKeyBytes);
            System.out.println("new key generated");
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
        }

        private void newKey() throws Exception {
            keyInfo.remove();
        }

        private byte[] aesEncrypt(byte[] plain) throws KafkaException {
            final ThreadAwareKeyInfo ki = keyInfo.get();

            try {
                final byte[] aesIv = new byte[IV_SIZE];
                ki.random.nextBytes(aesIv);
                ki.aesCipher.init(Cipher.ENCRYPT_MODE, ki.aesKey, new GCMParameterSpec(GCM_TAG_BIT_LENGTH, aesIv), new SecureRandom());
                ki.aesCipher.updateAAD(AAD_BYTES);
                System.out.println("ki.rsaEncyptedAesKey.length "+ki.rsaEncyptedAesKey.length);
                return concatenate(MAGIC_BYTES, new byte[] { (byte) ki.aesHash.length,
                        (byte) (ki.rsaEncyptedAesKey.length / RSA_MULTIPLICATOR), (byte) aesIv.length }, ki.aesHash, ki.rsaEncyptedAesKey,
                        aesIv, crypt(ki.aesCipher, plain));
            } catch (Exception e) {
                throw new KafkaException(e);
            }
        }
    }

    protected void init(int opMode, Map<String, ?> configs, boolean isKey) throws KafkaException {
        this.opMode = opMode;

        final String hashMethodProperty = (String) configs.get(CRYPTO_HASH_METHOD);
        
        if(hashMethodProperty != null && hashMethodProperty.length() != 0) {
            hashMethod = hashMethodProperty;
        }
        
        final String ignoreDecryptFailuresProperty = (String) configs.get(CRYPTO_IGNORE_DECRYPT_FAILURES);
        
        if(ignoreDecryptFailuresProperty != null && ignoreDecryptFailuresProperty.length() != 0) {
            ignoreDecryptFailures = Boolean.parseBoolean(ignoreDecryptFailuresProperty);
        }
        
        final String aesKeyLenProperty = (String) configs.get(CRYPTO_AES_KEY_LEN);
        
        if(aesKeyLenProperty != null && aesKeyLenProperty.length() != 0) {
            aesKeyLen = Integer.parseInt(aesKeyLenProperty);
            if(aesKeyLen < 128 || aesKeyLen % 8 != 0) {
                throw new KafkaException("Invalid aes key size, should be 128, 192 or 256");
            }
        }
        
        try {
        	String rsaPrivateKeyFile = (String) configs.get(CRYPTO_RSA_PRIVATEKEY_FILEPATH);
        	String rsaPublicKeyFile = (String) configs.get(CRYPTO_RSA_PUBLICKEY_FILEPATH);
        	
            if (opMode == Cipher.DECRYPT_MODE) {
                //Consumer
                consumerCryptoBundle = new ConsumerCryptoBundle(createRSAPrivateKey(readBytesFromFile(rsaPrivateKeyFile)),createRSAPublicKey(readBytesFromFile(rsaPublicKeyFile)));
            } else {
                //Producer
                producerCryptoBundle = new ProducerCryptoBundle(createRSAPublicKey(readBytesFromFile(rsaPublicKeyFile)),createRSAPrivateKey(readBytesFromFile(rsaPrivateKeyFile)));
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
            return consumerCryptoBundle.aesDecrypt(array);
        } else {
            //Producer
            byte[] e = producerCryptoBundle.aesEncrypt(array);
            System.out.println("aes encrypt ok");
            return e;
        }
    }

    /**
     * Generate new AES key for the current thread
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

    private static PrivateKey createRSAPrivateKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance(KEY_FACTORY, BC);
        return kf.generatePrivate(spec);
    }

    private static SecretKey createAESSecretKey(byte[] encodedKey) {
        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }

        return new SecretKeySpec(encodedKey, AES);
    }

    private static PublicKey createRSAPublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
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

    private byte[] hash(byte[] toHash) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashMethod);
            md.update(toHash);
            return md.digest();
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    private static byte[] crypt(Cipher c, byte[] plain) throws IllegalBlockSizeException, BadPaddingException {
        return c.doFinal(plain);
    }

    private static byte[] crypt(Cipher c, byte[] plain, int offset, int len) throws IllegalBlockSizeException, BadPaddingException {
        return c.doFinal(plain, offset, len);
    }
    
    public static byte[] concatenate(byte[] a, byte[] b, byte[] c, byte[] d, byte[] e, byte[] f) {
        if (a != null && b != null && c != null && d != null && e != null && f != null) {
            byte[] rv = new byte[a.length + b.length + c.length + d.length + e.length + f.length];
            System.arraycopy(a, 0, rv, 0, a.length);
            System.arraycopy(b, 0, rv, a.length, b.length);
            System.arraycopy(c, 0, rv, a.length + b.length, c.length);
            System.arraycopy(d, 0, rv, a.length + b.length + c.length, d.length);
            System.arraycopy(e, 0, rv, a.length + b.length + c.length + d.length, e.length);
            System.arraycopy(f, 0, rv, a.length + b.length + c.length + d.length + e.length, f.length);
            return rv;
        } else {
            throw new IllegalArgumentException("arrays must not be null");
        }
    }
}
