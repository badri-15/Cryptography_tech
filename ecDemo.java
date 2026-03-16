import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;

public class ecDemo {

    // ═══════════════════════════════════════════════════════════
    //  1. GENERATE ECC KEY PAIR
    // ═══════════════════════════════════════════════════════════
    public static KeyPair generateKeyPair() throws Exception {
        // Use NIST P-256 curve (secp256r1) - most widely used ECC curve
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecSpec, new SecureRandom());
        return kpg.generateKeyPair();
    }

    // ═══════════════════════════════════════════════════════════
    //  2. ECDH - COMPUTE SHARED SECRET
    // ═══════════════════════════════════════════════════════════
    public static byte[] computeSharedSecret(PrivateKey myPrivateKey,
                                              PublicKey theirPublicKey)
            throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
        keyAgree.init(myPrivateKey);
        keyAgree.doPhase(theirPublicKey, true);
        return keyAgree.generateSecret();
    }

    // ═══════════════════════════════════════════════════════════
    //  3. AES ENCRYPTION using shared secret
    // ═══════════════════════════════════════════════════════════
    public static byte[] aesEncrypt(String plainText, byte[] keyBytes)
            throws Exception {
        // Use first 16 bytes of shared secret as AES-128 key
        SecretKeySpec aesKey = new SecretKeySpec(keyBytes, 0, 16, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    // ═══════════════════════════════════════════════════════════
    //  4. AES DECRYPTION using shared secret
    // ═══════════════════════════════════════════════════════════
    public static String aesDecrypt(byte[] cipherText, byte[] keyBytes)
            throws Exception {
        SecretKeySpec aesKey = new SecretKeySpec(keyBytes, 0, 16, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(cipherText);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════
    //  5. ECDSA - DIGITAL SIGNATURE (Sign)
    // ═══════════════════════════════════════════════════════════
    public static byte[] signData(byte[] data, PrivateKey privateKey)
            throws Exception {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(privateKey, new SecureRandom());
        ecdsaSign.update(data);
        return ecdsaSign.sign();
    }

    // ═══════════════════════════════════════════════════════════
    //  6. ECDSA - DIGITAL SIGNATURE (Verify)
    // ═══════════════════════════════════════════════════════════
    public static boolean verifySignature(byte[] data, byte[] signature,
                                           PublicKey publicKey)
            throws Exception {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(data);
        return ecdsaVerify.verify(signature);
    }

    // ═══════════════════════════════════════════════════════════
    //  HELPER - Print separator line
    // ═══════════════════════════════════════════════════════════
    public static void printSection(String title) {
        System.out.println("\n╔══════════════════════════════════════════════╗");
        System.out.printf( "║  %-44s║%n", title);
        System.out.println("╚══════════════════════════════════════════════╝");
    }

    // ═══════════════════════════════════════════════════════════
    //  MAIN METHOD
    // ═══════════════════════════════════════════════════════════
    public static void main(String[] args) {

        try {
            System.out.println("╔══════════════════════════════════════════════╗");
            System.out.println("║     ECC - Elliptic Curve Cryptography        ║");
            System.out.println("║     Curve: secp256r1 (NIST P-256)            ║");
            System.out.println("╚══════════════════════════════════════════════╝");

            // ── STEP 1: Key Generation ──────────────────────────────────────
            printSection("STEP 1: Key Pair Generation");

            KeyPair aliceKeyPair = generateKeyPair();
            KeyPair bobKeyPair   = generateKeyPair();

            String alicePubKey = Base64.getEncoder()
                .encodeToString(aliceKeyPair.getPublic().getEncoded());
            String bobPubKey   = Base64.getEncoder()
                .encodeToString(bobKeyPair.getPublic().getEncoded());

            System.out.println("Alice's Public Key:");
            System.out.println("  " + alicePubKey.substring(0, 40) + "...");
            System.out.println("Alice's Private Key:");
            System.out.println("  " + Base64.getEncoder()
                .encodeToString(aliceKeyPair.getPrivate().getEncoded())
                .substring(0, 40) + "...");

            System.out.println("\nBob's Public Key:");
            System.out.println("  " + bobPubKey.substring(0, 40) + "...");
            System.out.println("Bob's Private Key:");
            System.out.println("  " + Base64.getEncoder()
                .encodeToString(bobKeyPair.getPrivate().getEncoded())
                .substring(0, 40) + "...");

            // ── STEP 2: ECDH Key Exchange ───────────────────────────────────
            printSection("STEP 2: ECDH Key Exchange");

            byte[] aliceSharedSecret = computeSharedSecret(
                aliceKeyPair.getPrivate(), bobKeyPair.getPublic()
            );
            byte[] bobSharedSecret   = computeSharedSecret(
                bobKeyPair.getPrivate(), aliceKeyPair.getPublic()
            );

            System.out.println("Alice computed shared secret:");
            System.out.println("  " + Base64.getEncoder()
                .encodeToString(aliceSharedSecret));
            System.out.println("\nBob computed shared secret:");
            System.out.println("  " + Base64.getEncoder()
                .encodeToString(bobSharedSecret));

            boolean secretsMatch = Arrays.equals(aliceSharedSecret, bobSharedSecret);
            System.out.println("\nSecrets Match: " + secretsMatch
                + (secretsMatch ? " ✓ (Key exchange successful!)" : " ✗ (Error!)"));

            // ── STEP 3: Encrypt Message ─────────────────────────────────────
            printSection("STEP 3: Encrypt Message (Alice → Bob)");

            String originalMessage = "Hello Bob! This is a secret message using ECC.";
            System.out.println("Original Message  : " + originalMessage);

            byte[] encryptedBytes = aesEncrypt(originalMessage, aliceSharedSecret);
            String encryptedB64   = Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("Encrypted (Base64): " + encryptedB64);

            // ── STEP 4: Decrypt Message ─────────────────────────────────────
            printSection("STEP 4: Decrypt Message (Bob decrypts)");

            String decryptedMessage = aesDecrypt(encryptedBytes, bobSharedSecret);
            System.out.println("Decrypted Message : " + decryptedMessage);
            System.out.println("Decryption Success: "
                + originalMessage.equals(decryptedMessage) + " ✓");

            // ── STEP 5: Digital Signature ───────────────────────────────────
            printSection("STEP 5: Digital Signature (ECDSA)");

            byte[] messageBytes = originalMessage.getBytes(StandardCharsets.UTF_8);
            byte[] signature    = signData(messageBytes, aliceKeyPair.getPrivate());

            System.out.println("Message   : " + originalMessage);
            System.out.println("Signature : "
                + Base64.getEncoder().encodeToString(signature).substring(0, 40) + "...");

            // ── STEP 6: Verify Signature ────────────────────────────────────
            printSection("STEP 6: Verify Signature");

            boolean validSignature = verifySignature(
                messageBytes, signature, aliceKeyPair.getPublic()
            );
            System.out.println("Signature Valid (original message) : "
                + validSignature + " ✓");

            // Tamper test - change message and verify again
            byte[] tamperedBytes = "Tampered message!".getBytes(StandardCharsets.UTF_8);
            boolean tamperedValid = verifySignature(
                tamperedBytes, signature, aliceKeyPair.getPublic()
            );
            System.out.println("Signature Valid (tampered message)  : "
                + tamperedValid + " ✗ (correctly rejected!)");

            // ── SUMMARY ─────────────────────────────────────────────────────
            printSection("SUMMARY");
            System.out.println("  ECC Curve Used     : secp256r1 (NIST P-256)");
            System.out.println("  Key Exchange       : ECDH (Elliptic Curve DH)");
            System.out.println("  Encryption         : AES-128 (ECB mode)");
            System.out.println("  Digital Signature  : ECDSA with SHA-256");
            System.out.println("  Key Exchange OK    : " + secretsMatch);
            System.out.println("  Encryption OK      : " + originalMessage.equals(decryptedMessage));
            System.out.println("  Signature OK       : " + validSignature);
            System.out.println("  Tamper Detection   : " + !tamperedValid);
            System.out.println("\n  All operations completed successfully!");

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
