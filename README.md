# FreeOTP Dump Tool

Warning: ai generated code and some features untested

A Java-based tool to decrypt and export FreeOTP Android backup files. Supports exporting to JSON, Aegis Authenticator format, and provides utilities for analyzing backup integrity.

## Features

- ✅ Decrypt FreeOTP Android backup files (Java serialization format)
- ✅ Export to portable JSON format
- ✅ Export to Aegis Authenticator import format
- ✅ Validate backup integrity and detect missing secrets
- ✅ Import JSON back to FreeOTP backup format
- ✅ Debug mode for troubleshooting

## Usage

Grab jar file from [Releases](https://github.com/akostadinov/freeotp-export/releases) or see the [Building](#building)

### Basic Decryption and Display

```bash
java -jar freeotp-dump-1.0-SNAPSHOT-jar-with-dependencies.jar backup.xml
```

You'll be prompted for your backup password. The tool will display all decrypted tokens with their secrets in Base32 format.

### Export to JSON

```bash
java -jar freeotp-dump-1.0-SNAPSHOT-jar-with-dependencies.jar backup.xml --json=output.json
```

Creates a portable JSON file with all tokens:
```json
{
  "version": 1,
  "exportDate": 1773264384189,
  "tokens": [
    {
      "uuid": "77777777-1111-2222-3333-444444444444",
      "secret": "AABBCCDDEEFF0011",
      "issuer": "GitHub",
      "label": "test",
      "algorithm": "SHA1",
      "digits": 6,
      "period": 30,
      "type": "TOTP"
    }
  ]
}
```

### Export to Aegis Format

```bash
java -jar freeotp-dump-1.0-SNAPSHOT-jar-with-dependencies.jar backup.xml --aegis=aegis.json
```

Creates a JSON file that can be imported directly into Aegis Authenticator.

### Import JSON to FreeOTP Format

```bash
java -cp freeotp-dump-1.0-SNAPSHOT-jar-with-dependencies.jar dev.ak.FreeOtpImport input.json output.xml "password"
```

Converts a JSON export back to FreeOTP backup format with encryption.

### Debug Mode

```bash
java -jar freeotp-dump-1.0-SNAPSHOT-jar-with-dependencies.jar backup.xml --debug
```

Shows detailed processing information including:
- File structure analysis
- UUID processing steps
- Decryption attempts
- Metadata parsing

### Leak Secrets (for debugging only)

```bash
java -jar freeotp-dump-1.0-SNAPSHOT-jar-with-dependencies.jar backup.xml --debug --leak-secrets
```

### Password from File

```bash
cat password.txt | java -jar freeotp-dump-1.0-SNAPSHOT-jar-with-dependencies.jar backup.xml
```

Or use `printf` to avoid trailing newlines:
```bash
printf '%s' "your-password" | java -jar freeotp-dump-1.0-SNAPSHOT-jar-with-dependencies.jar backup.xml
```

### Dump Backup Contents

```bash
javac DumpBackup.java
java DumpBackup backup.xml
```

Displays all entries in the backup file for manual inspection.

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--json=FILE` | Export tokens to JSON format |
| `--aegis=FILE` | Export tokens to Aegis Authenticator format |
| `--debug` | Enable debug output |
| `--leak-secrets` | Display encryption keys (debug only) |
| `--try-legacy-kek` | Try legacy key sizes (192/128-bit) |
| `--try-norms` | Try Unicode normalization variants |

## How It Works

1. **Read Backup**: Parses Java serialized HashMap from backup file
2. **Decrypt Master Key**: Uses PBKDF2-HMAC-SHA512 to derive KEK from password
3. **Decrypt Tokens**: Uses master key to decrypt individual token secrets
4. **Export**: Converts to requested format (console, JSON, Aegis)

### Encryption Details

- **KEK Derivation**: PBKDF2-HMAC-SHA512, 100,000 iterations, salt.length * 8 bits
- **Token Encryption**: AES-256-GCM with AAD (Additional Authenticated Data)
- **AAD**: Token algorithm name (e.g., "AES", "HmacSHA1")

## Building

### Requirements

- Java 11 or higher
- Maven 3.6 or higher

```bash
mvn clean package
```

This creates `target/freeotp-dump-1.0-SNAPSHOT-jar-with-dependencies.jar`

## Troubleshooting

### "Failed to decrypt masterKey"

- Verify password is correct (no trailing newlines)
- Try `--try-norms` flag for Unicode password issues
- Check backup file isn't corrupted

### "Token has metadata but no secret"

This is expected for tokens that were:
- Imported without secrets
- Saved with `tokendata_only=true`
- Overwritten by duplicate UUIDs

The tool correctly reports these as missing secrets.

### "Not a Java serialization stream"

The backup file format is incorrect. FreeOTP backups should start with `AC ED 00 05` (Java magic bytes).

## Security Notes

- Passwords are read securely (no echo) when using console input
- Passwords are cleared from memory after use
- Use `--leak-secrets` only in secure environments
- JSON exports contain plaintext secrets - protect them accordingly

## Contributing

This tool is based on FreeOTP Android's encryption logic. Contributions are welcome under the Apache 2.0 license.

## License

Apache License 2.0 - See LICENSE file for details.

This project is compatible with and based on FreeOTP Android:
https://github.com/freeotp/freeotp-android
