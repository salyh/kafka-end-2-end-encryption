package de.saly.kafka.crypto;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.UUID;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class ECKeyGen {
    
    public static void main(String[] args) throws Exception {
        String uuid = UUID.randomUUID().toString();
        File pubKey = new File("ec_publickey_" + uuid);
        File privKey = new File("ec_privatekey_" + uuid);

        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ECParameterSpec ecSpec=new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", new BouncyCastleProvider());
        keyGen.initialize(ecSpec, new SecureRandom());
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
