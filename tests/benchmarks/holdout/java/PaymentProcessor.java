import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Encrypts card numbers for the acquirer and signs webhook callbacks. */
public class PaymentProcessor {
    private static final String CARD_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final int RSA_BITS = 2048;

    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(RSA_BITS);
        KeyPair acquirer = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance(CARD_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, acquirer.getPublic());
        byte[] card = cipher.doFinal("4111111111111111".getBytes(StandardCharsets.UTF_8));

        // Cipher legacy = Cipher.getInstance("DES");   (removed in 2023)
        System.out.println("DESede and SHA1withRSA are no longer used here");

        MessageDigest idem = MessageDigest.getInstance("SHA-256");
        byte[] key = idem.digest(card);

        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        Mac webhook = Mac.getInstance("HmacSHA1");
        webhook.init(new SecretKeySpec(secret, "HmacSHA1"));
        System.out.println(webhook.doFinal(key).length);
    }
}
