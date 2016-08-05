package de.saly.kafka.crypto;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.UUID;

public class RsaKeyGen {
    
    public static void main(String[] args) throws Exception {
        int keysize = (args != null && args.length > 0) ? Integer.parseInt(args[0]) : 2048;
        System.out.println("Keysize: "+keysize+" bits");
        String uuid = UUID.randomUUID().toString();
        File pubKey = new File("rsa_publickey_" + keysize + "_" + uuid);
        File privKey = new File("rsa_privatekey_" + keysize + "_" + uuid);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keysize);
        KeyPair pair = keyGen.genKeyPair();
        byte[] publicKey = pair.getPublic().getEncoded();
        byte[] privateKey = pair.getPrivate().getEncoded();

        FileOutputStream fout = new FileOutputStream(pubKey);
        fout.write(publicKey);
        fout.close();

        fout = new FileOutputStream(privKey);
        fout.write(privateKey);
        fout.close();

        System.out.println(pubKey.getAbsolutePath());
        System.out.println(privKey.getAbsolutePath());
    }
    
}
