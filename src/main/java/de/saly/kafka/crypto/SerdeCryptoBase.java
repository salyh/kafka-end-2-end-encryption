package de.saly.kafka.crypto;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
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
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.cipher.CryptoCipherFactory.CipherProvider;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.utils.Utils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class SerdeCryptoBase {

	public static final String CRYPTO_PRIVATEKEY_FILEPATH = "crypto.privatekey.filepath";
    public static final String CRYPTO_PUBLICKEY_FILEPATH = "crypto.publickey.filepath";
    public static final String CRYPTO_IGNORE_DECRYPT_FAILURES = "crypto.ignore_decrypt_failures";
    public static final String CRYPTO_AES_KEY_LEN = "crypto.aes.key_len";
    
    private static final String ECDH = "ECDH"; //Elliptic-curve Diffie–Hellman
    static final byte[] MAGIC_BYTES = new byte[] { (byte) 0xBD, (byte) 0xDD };
    private static final int MAGIC_BYTES_LENGTH = MAGIC_BYTES.length;
    private static final int HEADER_LENGTH = MAGIC_BYTES_LENGTH + 1;
    private static final int IV_SIZE = 12; //12 bytes initialization vector
    private static final int GCM_TAG_BIT_LENGTH = 128 ;
    private static final byte[] INFO_BYTES = "KafkaE2ES".getBytes(StandardCharsets.US_ASCII);
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"; //padding is part of gcm itself

    private static final BouncyCastleProvider BC = new BouncyCastleProvider();
    private int opMode;
    private int aesKeyLen = 128;
    private boolean ignoreDecryptFailures = false;
    private ProducerCryptoBundle producerCryptoBundle = null;
    private ConsumerCryptoBundle consumerCryptoBundle = null;
    
    private Properties cryptoProps;
    
    //not thread safe
    private class ConsumerCryptoBundle {

        private final Key key;
        private final CryptoCipher decryptingCipher;
        
        private ConsumerCryptoBundle(PrivateKey privateKey, PublicKey publicKey) throws Exception {     
        	final byte[] aesKey = deriveAESSecretKey(publicKey, privateKey);
            decryptingCipher = org.apache.commons.crypto.utils.Utils.getCipherInstance(AES_GCM_TRANSFORMATION, cryptoProps);
            key = new SecretKeySpec(aesKey, "AES");
        }

        private byte[] decrypt(byte[] encrypted) throws KafkaException {
            try {
                if (encrypted[0] == MAGIC_BYTES[0] && encrypted[1] == MAGIC_BYTES[1]) {
                    final byte ivLen = encrypted[2];
                    final int offset = HEADER_LENGTH + ivLen;
                    final byte[] iv = Arrays.copyOfRange(encrypted, HEADER_LENGTH, HEADER_LENGTH + ivLen);
                    final byte[] ciphertext = Arrays.copyOfRange(encrypted, offset, encrypted.length);
                    final byte[] plainOutput = new byte[ciphertext.length - (GCM_TAG_BIT_LENGTH >> 3)];
                    final GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv);
                    decryptingCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                    final int len = decryptingCipher.doFinal(ciphertext, 0, ciphertext.length, plainOutput, 0);
                    return plainOutput.length!=len?Arrays.copyOf(plainOutput, len):plainOutput;
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
        private final SecureRandom random = new SecureRandom();
        private final Key key;
        private final CryptoCipher encryptingCipher;

        protected ThreadAwareKeyInfo(PublicKey publicKey, PrivateKey privateKey) throws Exception {
            final byte[] aesKey = deriveAESSecretKey(publicKey, privateKey);
            encryptingCipher = org.apache.commons.crypto.utils.Utils.getCipherInstance(AES_GCM_TRANSFORMATION, cryptoProps);
            key = new SecretKeySpec(aesKey, "AES");
        }
    }

    //thread safe
    private class ProducerCryptoBundle {

        private final PublicKey publicKey;
        private final PrivateKey privateKey;
    	
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

        private ProducerCryptoBundle(PublicKey publicKey, PrivateKey privateKey) throws Exception {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        private void newKey() throws Exception {
            keyInfo.remove();
        }

        private byte[] encrypt(byte[] plain) throws KafkaException {
            final ThreadAwareKeyInfo ki = keyInfo.get();

            try {
            	final byte[] encOutput = new byte[plain.length + (GCM_TAG_BIT_LENGTH >> 3)];
                final byte[] aesIv = new byte[IV_SIZE];
                ki.random.nextBytes(aesIv);
                final GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, aesIv);
                ki.encryptingCipher.init(Cipher.ENCRYPT_MODE, ki.key, ivSpec);
                int len = ki.encryptingCipher.doFinal(plain, 0, plain.length, encOutput, 0);
                return concatenate(MAGIC_BYTES, 
                		new byte[] { (byte) aesIv.length},
                        aesIv, 
                        encOutput.length!=len?Arrays.copyOf(encOutput, len):encOutput);
                
            } catch (Exception e) {
                throw new KafkaException(e);
            }
        }
    }

    protected void init(int opMode, Map<String, ?> configs, boolean isKey) throws KafkaException {
        this.opMode = opMode;
        
        //String cipherClass = CipherProvider.JCE.getClassName();
        String cipherClass = CipherProvider.OPENSSL.getClassName();

    	cryptoProps = new Properties();
        cryptoProps.setProperty(CryptoCipherFactory.CLASSES_KEY,
                cipherClass);
        
        
        final String ignoreDecryptFailuresProperty = (String) configs.get(CRYPTO_IGNORE_DECRYPT_FAILURES);
        
        if(ignoreDecryptFailuresProperty != null && ignoreDecryptFailuresProperty.length() != 0) {
            ignoreDecryptFailures = Boolean.parseBoolean(ignoreDecryptFailuresProperty);
        }
        
        final String aesKeyLenProperty = (String) configs.get(CRYPTO_AES_KEY_LEN);
        
        if(aesKeyLenProperty != null && aesKeyLenProperty.length() != 0) {
            aesKeyLen = Integer.parseInt(aesKeyLenProperty);
            if(aesKeyLen != 128 && aesKeyLen != 192 && aesKeyLen != 256) {
                throw new KafkaException("Invalid aes key size, should be 128, 192 or 256");
            }
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
            return producerCryptoBundle.encrypt(array);
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
        KeyFactory kf = KeyFactory.getInstance(ECDH, BC);
        return kf.generatePrivate(spec);
    }

    private static PublicKey createPublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance(ECDH, BC);
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

    private static byte[] concatenate(byte[] a, byte[] b, byte[] c, byte[] d) {
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
    
    private byte[] deriveAESSecretKey(PublicKey publicKey, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException {
    	final KeyAgreement ka = KeyAgreement.getInstance(ECDH, BC);
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        final HKDFBytesGenerator kDF1BytesGenerator = new HKDFBytesGenerator(new SHA256Digest());     
        kDF1BytesGenerator.init(new HKDFParameters(ka.generateSecret(), null, INFO_BYTES));
        final byte[] key = new byte[aesKeyLen/8];
        kDF1BytesGenerator.generateBytes(key, 0, aesKeyLen/8);
        return key;
    }
}
