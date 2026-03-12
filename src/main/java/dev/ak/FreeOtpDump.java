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
import java.security.spec.KeySpec;
import java.text.Normalizer;
import java.util.*;
import java.util.regex.Pattern;

public class FreeOtpDump {

    private static final byte[] JAVA_MAGIC = new byte[]{(byte)0xAC, (byte)0xED, 0x00, 0x05};
    private static final Pattern UUID_RE = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private static final ObjectMapper M = new ObjectMapper();
    private static final Base32 B32 = new Base32();

    static class Encrypted {
        public String mCipher;       // "AES/GCM/NoPadding"
        public int[]  mCipherText;   // ciphertext||tag
        public int[]  mParameters;   // AlgorithmParameters(GCM).getEncoded()
        public String mToken;        // "AES" or "HmacSHA1"/"HmacSHA256"/"HmacSHA512" (for per-token keys)
    }
    static class MasterKey {
        public String    mAlgorithm;     // "PBKDF2withHmacSHA512"
        public Encrypted mEncryptedKey;  // AES-GCM blob of master AES key
        public int       mIterations;    // e.g. 100000
        public int[]     mSalt;          // PBKDF2 salt (int[] -> bytes)
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java -jar freeotp-dump.jar <backup-file> [--debug] [--leak-secrets] [--json=out.json] [--aegis=out.json] [--try-legacy-kek] [--try-norms]");
            System.exit(2);
        }

        // Flags
        File f = null;
        String aegisOut = null;
        String jsonOut = null;
        boolean debug = false;
        boolean leak = false;
        boolean tryLegacyKek = false;
        boolean tryNorms = false;

        for (String a : args) {
            if (a.equals("--debug")) debug = true;
            else if (a.equals("--leak-secrets")) leak = true;
            else if (a.equals("--try-legacy-kek")) tryLegacyKek = true;
            else if (a.equals("--try-norms")) tryNorms = true;
            else if (a.startsWith("--aegis")) {
                String[] kv = a.split("=", 2);
                if (kv.length == 2) aegisOut = kv[1];
                else {
                    System.err.println("Use --aegis=/path/to/out.json");
                    System.exit(2);
                }
            } else if (a.startsWith("--json")) {
                String[] kv = a.split("=", 2);
                if (kv.length == 2) jsonOut = kv[1];
                else {
                    System.err.println("Use --json=/path/to/out.json");
                    System.exit(2);
                }
            } else if (!a.startsWith("--")) {
                f = new File(a);
            }
        }
        if (f == null) {
            System.err.println("Specify backup file path.");
            System.exit(2);
        }

        // 1) Read & verify header
        byte[] raw = readAllBytes(f);
        if (debug) System.out.printf("[debug] file size=%,d, head=%s%n", raw.length, hex(Arrays.copyOf(raw, Math.min(32, raw.length))));
        if (!isJavaStream(raw)) {
            System.err.printf("[!] Not a Java serialization stream (head=%s)%n", hex(Arrays.copyOf(raw, Math.min(32, raw.length))));
            System.exit(2);
        }
        System.out.printf("[+] Read %,d bytes; Java magic OK%n", raw.length);

        // 2) Deserialize HashMap<String, ?>
        Map<?,?> serialized;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(raw))) {
            Object o = ois.readObject();
            if (!(o instanceof Map)) {
                System.err.println("[!] Top-level object is not a Map");
                System.exit(2);
            }
            serialized = (Map<?,?>) o;
        }
        System.out.printf("[+] Top-level map entries: %d%n", serialized.size());

        // Normalize to String->String
        Map<String,String> map = new LinkedHashMap<>();
        for (Map.Entry<?,?> e : serialized.entrySet()) {
            map.put(String.valueOf(e.getKey()), e.getValue() == null ? null : String.valueOf(e.getValue()));
        }
        if (debug) System.out.println("[debug] All keys: " + map.keySet());

        // 3) Secure password prompt (no echo)
        char[] passwordChars = readPassword("Enter FreeOTP backup password: ");
        if (passwordChars == null) {
            System.err.println("[!] Could not read password from console; aborting.");
            System.exit(2);
        }

        // 4) Parse masterKey JSON exactly like app (Gson/Jackson equivalent)
        String masterKeyJson = map.get("masterKey");
        if (masterKeyJson == null) {
            System.err.println("[!] masterKey entry not found; cannot proceed.");
            System.exit(2);
        }
        MasterKey mk = parseMasterKey(masterKeyJson);
        System.out.printf("[i] masterKey: algo=%s, iterations=%d, saltLen=%d, enc.cipher=%s, token=%s%n",
                mk.mAlgorithm, mk.mIterations, mk.mSalt.length, mk.mEncryptedKey.mCipher, mk.mEncryptedKey.mToken);

        // 5) Derive KEK via PBKDF2 using salt.length * 8 as key length (FreeOTP standard)
        byte[] masterKey = null;
        List<char[]> passVariants = new ArrayList<>();
        passVariants.add(passwordChars);                 // exact chars (default)
        if (tryNorms) { // attempt NFC & NFKC after normal attempt
            passVariants.add(Normalizer.normalize(new String(passwordChars), Normalizer.Form.NFC).toCharArray());
            passVariants.add(Normalizer.normalize(new String(passwordChars), Normalizer.Form.NFKC).toCharArray());
        }

        for (char[] pass : passVariants) {
            try {
                byte[] kek = pbkdf2(pass, mk.mSalt, mk.mIterations, mk.mAlgorithm);
                if (leak) System.out.printf("[leak] KEK: %s%n", hex(kek));
                masterKey = decryptGcm(kek, mk.mEncryptedKey, "masterKey");
                if (leak) System.out.printf("[leak] masterKey: %s%n", hex(masterKey));
                System.out.printf("[+] masterKey decrypted successfully%n");
                break;
            } catch (AEADBadTagException bad) {
                if (debug) System.out.printf("[debug] masterKey: wrong tag with password variant; trying next…%n");
            } catch (GeneralSecurityException gse) {
                if (debug) System.out.printf("[debug] masterKey: failed: %s%n", gse);
            }
        }

        // wipe all pass variants
        for (char[] pv : passVariants) Arrays.fill(pv, '\0');

        if (masterKey == null) {
            System.err.println("[!] Failed to decrypt masterKey (wrong password/tampered backup).");
            System.exit(2);
        }

        // 6) Walk entries, decrypt each token secret with the master key
        int secrets = 0, metas = 0;
        Map<String, byte[]> uuidToSecret = new LinkedHashMap<>();
        Map<String, JsonNode> uuidToMeta = new LinkedHashMap<>();

        for (Map.Entry<String,String> e : map.entrySet()) {
            String k = e.getKey();
            if ("masterKey".equals(k)) continue;
            String v = e.getValue();

            if (k.endsWith("-token")) {
                String uuid = k.substring(0, k.length() - 6);
                if (debug) System.out.printf("[debug] Found metadata for UUID: %s%n", uuid);
                try {
                    uuidToMeta.put(uuid, M.readTree(v));
                    metas++;
                } catch (Exception ex) {
                    System.out.printf("[!] Failed to parse metadata for %s: %s%n", uuid, ex);
                }
                continue;
            }

            if (UUID_RE.matcher(k).matches()) {
                if (debug) System.out.printf("[debug] Processing secret for UUID: %s%n", k);
                try {
                    // Per-token secret: {"key":"{...GCM params...}"}
                    JsonNode outer = M.readTree(v);
                    JsonNode inner = M.readTree(outer.get("key").asText());
                    Encrypted enc = M.treeToValue(inner, Encrypted.class);

                    byte[] pt = decryptGcm(masterKey, enc, "token:" + k);
                    uuidToSecret.put(k, pt);
                    secrets++;
                    if (debug) System.out.printf("[debug] Successfully decrypted secret for UUID: %s%n", k);
                } catch (AEADBadTagException bad) {
                    System.out.printf("[!] Failed to decrypt secret for %s: Wrong password/tag%n", k);
                } catch (Exception ex) {
                    System.out.printf("[!] Failed to decrypt secret for %s: %s%n", k, ex);
                }
            } else if (debug && !k.equals("masterKey")) {
                System.out.printf("[debug] Skipping non-UUID key: %s%n", k);
            }
        }

        System.out.printf("[+] Processed: %d entries; secrets: %d, metadata: %d%n", map.size(), secrets, metas);

        // 7) Print results & (optionally) write Aegis JSON
        System.out.println("\n=== Extracted Tokens ===\n");

        List<Map<String,Object>> aegisDb = new ArrayList<>();

        for (Map.Entry<String, byte[]> e : uuidToSecret.entrySet()) {
            String uuid = e.getKey();
            byte[] secret = e.getValue();
            JsonNode meta = uuidToMeta.get(uuid);

            String issuer = (meta != null && meta.hasNonNull("issuerInt")) ? meta.get("issuerInt").asText()
                           : (meta != null && meta.hasNonNull("issuerExt")) ? meta.get("issuerExt").asText()
                           : null;
            String label  = (meta != null && meta.hasNonNull("label")) ? meta.get("label").asText() : uuid;
            String algo   = (meta != null && meta.hasNonNull("algo")) ? meta.get("algo").asText().toUpperCase() : "SHA1";
            int    digits = (meta != null && meta.hasNonNull("digits")) ? meta.get("digits").asInt() : 6;
            int    period = (meta != null && meta.hasNonNull("period")) ? meta.get("period").asInt() : 30;
            String type   = (meta != null && meta.hasNonNull("type")) ? meta.get("type").asText() : "TOTP";

            String b32 = B32.encodeToString(secret).replace("=", "");

            System.out.printf(
                "UUID:   %s%nIssuer: %s%nLabel:  %s%nSecret: %s%nAlgo:   %s%nDigits: %d%nPeriod: %d%nType:   %s%n",
                uuid, issuer, label, b32, algo, digits, period, type);
            System.out.println("----------------------------------------");

            if (aegisOut != null) {
                Map<String,Object> rec = new LinkedHashMap<>();
                rec.put("type", "totp");
                rec.put("issuer", issuer);
                rec.put("name", label);
                rec.put("secret", b32);
                rec.put("digits", digits);
                rec.put("period", period);
                rec.put("algorithm", algo); // Aegis accepts "SHA1"/"SHA256"/"SHA512"
                aegisDb.add(rec);
            }
        }

        if (jsonOut != null) {
            Map<String,Object> root = new LinkedHashMap<>();
            root.put("version", 1);
            root.put("exportDate", System.currentTimeMillis());
            
            List<Map<String,Object>> tokensList = new ArrayList<>();
            
            for (Map.Entry<String, byte[]> e : uuidToSecret.entrySet()) {
                String uuid = e.getKey();
                byte[] secret = e.getValue();
                JsonNode meta = uuidToMeta.get(uuid);
                
                Map<String,Object> token = new LinkedHashMap<>();
                token.put("uuid", uuid);
                token.put("secret", B32.encodeToString(secret).replace("=", ""));
                
                if (meta != null) {
                    String issuer = (meta.hasNonNull("issuerInt")) ? meta.get("issuerInt").asText()
                                   : (meta.hasNonNull("issuerExt")) ? meta.get("issuerExt").asText()
                                   : "";
                    token.put("issuer", issuer);
                    token.put("label", meta.path("label").asText(""));
                    token.put("algorithm", meta.path("algo").asText("SHA1"));
                    token.put("digits", meta.path("digits").asInt(6));
                    token.put("period", meta.path("period").asInt(30));
                    token.put("type", meta.path("type").asText("TOTP"));
                }
                
                tokensList.add(token);
            }
            
            root.put("tokens", tokensList);
            
            try (Writer w = new OutputStreamWriter(new FileOutputStream(jsonOut), java.nio.charset.StandardCharsets.UTF_8)) {
                M.writerWithDefaultPrettyPrinter().writeValue(w, root);
                System.out.printf("[+] Wrote JSON export to: %s%n", jsonOut);
            }
        }
        
        if (aegisOut != null) {
            Map<String,Object> root = new LinkedHashMap<>();
            root.put("version", 1);
            root.put("database", aegisDb);
            try (Writer w = new OutputStreamWriter(new FileOutputStream(aegisOut), java.nio.charset.StandardCharsets.UTF_8)) {
                M.writerWithDefaultPrettyPrinter().writeValue(w, root);
                System.out.printf("[+] Wrote Aegis import JSON to: %s%n", aegisOut);
            }
        }
    }

    // ==== helpers replicating FreeOTP’s crypto path ====

    static byte[] pbkdf2(char[] passwordChars, int[] saltSigned, int iterations, String algorithm)
            throws GeneralSecurityException {
        byte[] salt = intsToBytes(saltSigned);
        // FreeOTP Android uses salt.length * 8 as key length, not a fixed 256
        int actualKeyLen = salt.length * 8;
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, iterations, actualKeyLen);
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);
            return f.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword(); // avoid lingering secrets
        }
    }

    static byte[] decryptGcm(byte[] key, Encrypted enc, String who)
            throws GeneralSecurityException {
        byte[] ct = intsToBytes(enc.mCipherText);

        // Build GCMParameterSpec from encoded AlgorithmParameters just like the app
        AlgorithmParameters params = AlgorithmParameters.getInstance("GCM");
        try {
            params.init(intsToBytes(enc.mParameters));  // AlgorithmParameters.init(byte[]) may throw IOException
        } catch (IOException io) {
            throw new GeneralSecurityException("Failed to parse GCM parameters for " + who, io);
        }
        GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey sk = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, sk, spec);
        
        // CRITICAL: Add AAD (Additional Authenticated Data) with token algorithm name
        // This must match what was used during encryption or GCM authentication will fail
        cipher.updateAAD(enc.mToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        
        return cipher.doFinal(ct); // Java expects ciphertext||tag
    }

    static byte[] intsToBytes(int[] a) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte)(a[i] & 0xFF);
        return out;
    }

    static boolean isJavaStream(byte[] b) {
        if (b.length < 4) return false;
        for (int i=0;i<4;i++) if (b[i]!=JAVA_MAGIC[i]) return false;
        return true;
    }

    static byte[] readAllBytes(File f) throws IOException {
        try (InputStream in = new FileInputStream(f)) {
            return in.readAllBytes();
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length*2);
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }

    static char[] readPassword(String prompt) throws IOException {
        Console c = System.console();
        if (c != null) return c.readPassword(prompt);
        // Fallback (no echo): best effort
        System.out.print(prompt);
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        return br.readLine().toCharArray();
    }

    static MasterKey parseMasterKey(String json) throws IOException {
        return M.readValue(json, MasterKey.class);
    }
}
