package com.acme.wallet;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class KeyAgreementService {
    private static final String CURVE = "secp256r1";
    private static final String WRAP = "DESede/CBC/PKCS5Padding";

    public KeyPair ephemeral() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(CURVE));
        return g.generateKeyPair();
    }

    public byte[] agree(PrivateKey mine, PublicKey theirs) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mine);
        ka.doPhase(theirs, true);
        return ka.generateSecret();
    }

    public byte[] wrap(byte[] key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance(WRAP);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        return c.doFinal(data);
    }

    public byte[] sign(PrivateKey k, byte[] m) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(k);
        s.update(m);
        return s.sign();
    }

    public byte[] tag(byte[] k, byte[] m) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(k, "HmacSHA512"));
        return mac.doFinal(m);
    }

    public String oneTimeCode() {
        return String.valueOf(new Random().nextInt(1_000_000));
    }
}
