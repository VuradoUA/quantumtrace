/** Release notes printer. The words Cipher, RSA and SHA1withRSA appear only in strings and comments. */
public class Notes {
    // Cipher c = Cipher.getInstance("DES");
    /* MessageDigest.getInstance("MD5") was removed */
    public static void main(String[] args) {
        String note = "Migrated from SHA1withRSA to ML-DSA";
        String cipher = "AES/ECB/PKCS5Padding is forbidden";
        System.out.println(note + " " + cipher);
    }
}
