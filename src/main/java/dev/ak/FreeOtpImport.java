package dev.ak;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.*;

/**
 * Import JSON tokens into FreeOTP backup format
 */
public class FreeOtpImport {
    
    private static final ObjectMapper M = new ObjectMapper();
    private static final Base32 B32 = new Base32();
    private static final SecureRandom RANDOM = new SecureRandom();
    
    static class Encrypted {
        public String mCipher;
        public int[] mCipherText;
        public int[] mParameters;
        public String mToken;
    }
    
    static class MasterKey {
        public String mAlgorithm;
        public Encrypted mEncryptedKey;
        public int mIterations;
        public int[] mSalt;
    }
    
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Usage: java -jar freeotp-import.jar <input.json> <output.xml> <password>");
            System.exit(2);
        }
        
        String jsonFile = args[0];
        String outputFile = args[1];
        String password = args[2];
        
        // Read JSON
        JsonNode root = M.readTree(new File(jsonFile));
        if (!root.has("tokens")) {
            System.err.println("Invalid JSON format: missing 'tokens' field");
            System.exit(2);
        }
        
        System.out.printf("[+] Reading JSON from: %s%n", jsonFile);
        
        // Generate master key
        byte[] salt = new byte[32];
        RANDOM.nextBytes(salt);
        
        byte[] masterKeyBytes = new byte[32];
        RANDOM.nextBytes(masterKeyBytes);
        
        int iterations = 100000;
        byte[] kek = pbkdf2(password.toCharArray(), salt, iterations, "PBKDF2WithHmacSHA512");
        
        // Encrypt master key
        Encrypted encryptedMasterKey = encryptGcm(kek, masterKeyBytes, "AES");
        
        MasterKey mk = new MasterKey();
        mk.mAlgorithm = "PBKDF2withHmacSHA512";
        mk.mEncryptedKey = encryptedMasterKey;
        mk.mIterations = iterations;
        mk.mSalt = bytesToInts(salt);
        
        // Build backup map
        Map<String, String> backup = new LinkedHashMap<>();
        backup.put("masterKey", M.writeValueAsString(mk));
        
        // Process tokens
        JsonNode tokens = root.get("tokens");
        int count = 0;
        
        for (JsonNode token : tokens) {
            String uuid = token.path("uuid").asText();
            String secretB32 = token.path("secret").asText();
            
            // Decode secret
            byte[] secret = B32.decode(secretB32);
            
            // Encrypt secret with master key
            Encrypted encryptedSecret = encryptGcm(masterKeyBytes, secret, "HmacSHA1");
            
            // Create secret entry
            Map<String, String> secretEntry = new LinkedHashMap<>();
            secretEntry.put("key", M.writeValueAsString(encryptedSecret));
            backup.put(uuid, M.writeValueAsString(secretEntry));
            
            // Create metadata entry
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("algo", token.path("algorithm").asText("SHA1"));
            metadata.put("digits", token.path("digits").asInt(6));
            metadata.put("period", token.path("period").asInt(30));
            metadata.put("type", token.path("type").asText("TOTP"));
            
            String issuer = token.path("issuer").asText("");
            if (!issuer.isEmpty()) {
                metadata.put("issuerInt", issuer);
                metadata.put("issuerExt", issuer);
            }
            
            String label = token.path("label").asText("");
            if (!label.isEmpty()) {
                metadata.put("label", label);
            }
            
            backup.put(uuid + "-token", M.writeValueAsString(metadata));
            count++;
        }
        
        System.out.printf("[+] Processed %d tokens%n", count);
        
        // Write as Java serialization
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(outputFile))) {
            oos.writeObject(backup);
        }
        
        System.out.printf("[+] Wrote FreeOTP backup to: %s%n", outputFile);
        System.out.println("[+] This backup can be imported into FreeOTP Android");
    }
    
    static byte[] pbkdf2(char[] password, byte[] salt, int iterations, String algorithm) 
            throws GeneralSecurityException {
        int keyLen = salt.length * 8;
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLen);
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);
            return f.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
    
    static Encrypted encryptGcm(byte[] key, byte[] plaintext, String tokenAlgo) 
            throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey sk = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, sk);
        
        // Add AAD
        cipher.updateAAD(tokenAlgo.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] params = cipher.getParameters().getEncoded();
        
        Encrypted enc = new Encrypted();
        enc.mCipher = "AES/GCM/NoPadding";
        enc.mCipherText = bytesToInts(ciphertext);
        enc.mParameters = bytesToInts(params);
        enc.mToken = tokenAlgo;
        
        return enc;
    }
    
    static int[] bytesToInts(byte[] bytes) {
        int[] ints = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            ints[i] = bytes[i] & 0xFF;
        }
        return ints;
    }
}
