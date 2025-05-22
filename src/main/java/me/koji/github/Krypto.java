package me.koji.github;

import me.koji.github.Exceptions.DecryptionFailed;
import me.koji.github.Exceptions.EncryptionFailed;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * Encryption and decryption.
 * @author Koji Usoki
 */
public final class Krypto {

    private static int BLOCK_SIZE = 16;
    private static int KEY_SIZE = 256;
    private static String IV_PATH = "krypto/iv";
    private static String SECRET_PATH = "krypto/secret";

    private static String DEFAULT_REFERENCE_KEY = "default";

    private static final String AES_METHOD = "AES/CBC/PKCS5Padding";

    private static boolean allowNullInput = true;
    private static boolean safeMode = false;

    private final String referenceKey;

    public static final class Configurator {
        public Configurator() { }
        /**
         * Sets block size.
         *
         * @param blockSize the block size
         */
        public Configurator setBlockSize(final int blockSize) {
            Krypto.BLOCK_SIZE = blockSize;

            return this;
        }

        /**
         * Sets key size.
         *
         * @param keySize the key size
         */
        public Configurator setKeySize(final int keySize) {
            Krypto.KEY_SIZE = keySize;

            return this;
        }

        /**
         * Sets where {@link IvParameterSpec} must be saved, the directory must already exist otherwise it will error.
         *
         * @param ivPath the iv path
         */
        public Configurator setIvPath(final String ivPath) {
            Krypto.IV_PATH = ivPath;

            return this;
        }

        /**
         * Sets where {@link SecretKey} must be saved, the directory must already exist otherwise it will error.
         *
         * @param secretPath the secret path
         */
        public Configurator setSecretPath(final String secretPath) {
            Krypto.SECRET_PATH = secretPath;

            return this;
        }

        /**
         * Sets if the code must accept null options. If false it will throw an exception when the input is null.
         * This is valid only if {@code safeMode} is disabled.
         *
         * @param allowNullInput the allow null input
         */
        public Configurator setAllowNullInput(final boolean allowNullInput) {
            Krypto.allowNullInput = allowNullInput;

            return this;
        }

        /**
         * Turns on/off the safe mode.
         * If enabled all exceptions will be caught in the encryption/decryption and the value returned will be the {@code input.toString()} or an empty string.
         *
         * @param safeMode the safe mode
         */
        public Configurator setSafeMode(final boolean safeMode) {
            Krypto.safeMode = safeMode;

            return this;
        }

        /**
         * Sets the global reference key.
         *
         * @param defaultReferenceKey the global reference key
         */
        public Configurator setGlobalReferenceKey(final String defaultReferenceKey) {
            Krypto.DEFAULT_REFERENCE_KEY = defaultReferenceKey;

            return this;
        }
    }

    /**
     * Creates a new Krypto instance, {@code referenceKey} parameter is used to save a file the {@link SecretKey} and {@link IvParameterSpec} data.
     *
     * @param referenceKey the reference key
     */
    public Krypto(final String referenceKey) {
        this.referenceKey = referenceKey;
    }

    private static IvParameterSpec getGuildIvParameter(final String referenceKey) throws IOException {
        try (FileInputStream fis = new FileInputStream(IV_PATH + "/" + referenceKey + ".dat")) {
            return new IvParameterSpec(fis.readAllBytes());
        } catch (FileNotFoundException exception){
            final byte[] iv = new byte[BLOCK_SIZE];

            new SecureRandom().nextBytes(iv);

            saveToFile(IV_PATH +"/" + referenceKey + ".dat", iv);

            return new IvParameterSpec(iv);
        }
    }

    private static SecretKey getGuildSecretKey(final String referenceKey) throws IOException, NoSuchAlgorithmException {
        try (FileInputStream secretKeyFile = new FileInputStream(SECRET_PATH + "/" + referenceKey + ".dat")) {
            return new SecretKeySpec(secretKeyFile.readAllBytes(), "AES");
        }catch (FileNotFoundException exception) {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(KEY_SIZE);

            final SecretKey secretKey = keyGenerator.generateKey();
            saveToFile(SECRET_PATH +"/" + referenceKey + ".dat", secretKey.getEncoded());

            return secretKey;
        }
    }

    /**
     * Save to file.
     *
     * @param filePath the file path
     * @param data     the data
     * @throws IOException the io exception
     */
    public static void saveToFile(final String filePath, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(data);
        }
    }

    /**
     * Global encrypt string.
     *
     * @param input the input
     * @return the string
     * @throws EncryptionFailed the encryption failed
     */
    public static String defaultEncrypt(final Object input) throws EncryptionFailed {
        return Krypto.encrypt(DEFAULT_REFERENCE_KEY, input);
    }

    /**
     * Global decrypt string.
     *
     * @param input the input
     * @return the string
     * @throws DecryptionFailed the encryption failed
     */
    public static String defaultDecrypt(final Object input) throws DecryptionFailed {
        return Krypto.decrypt(DEFAULT_REFERENCE_KEY, input);
    }

    /**
     * Global encrypt list.
     *
     * @param input the input
     * @return the list
     * @throws EncryptionFailed the encryption failed
     */
    public static List<String> defaultEncrypt(final List<String> input) throws EncryptionFailed {
        return Krypto.encrypt(DEFAULT_REFERENCE_KEY, input);
    }

    /**
     * Global decrypt list.
     *
     * @param input the input
     * @return the list
     * @throws DecryptionFailed the decryption failed
     */
    public static List<String> defaultDecrypt(final List<String> input) throws DecryptionFailed {
        return Krypto.decrypt(DEFAULT_REFERENCE_KEY, input);
    }

    /**
     * Encrypt list.
     *
     * @param referenceKey the reference key
     * @param inputList    the input list
     * @return the list
     * @throws EncryptionFailed the encryption failed
     */
    public static List<String> encrypt(final String referenceKey, final List<String> inputList) throws EncryptionFailed {
        if (inputList == null)
            return null;

        final ArrayList<String> encryptedContent = new ArrayList<>();

        for (final String input : inputList) {
            encryptedContent.add(encrypt(referenceKey, input));
        }

        return encryptedContent;
    }

    /**
     * Decrypt list.
     *
     * @param referenceKey the reference key
     * @param inputList    the input list
     * @return the list
     * @throws DecryptionFailed the decryption failed
     */
    public static List<String> decrypt(final String referenceKey, final List<String> inputList) throws DecryptionFailed {
        if (inputList == null)
            return null;

        final ArrayList<String> decryptedContent = new ArrayList<>();

        for (final String input : inputList) {
            decryptedContent.add(decrypt(referenceKey, input));
        }

        return decryptedContent;
    }


    /**
     * Encrypt string.
     *
     * @param referenceKey the reference key
     * @param input        the input
     * @return the string
     * @throws EncryptionFailed the encryption failed
     */
    public static String encrypt(final String referenceKey, final Object input) throws EncryptionFailed {
        if (referenceKey == null)
            throw new EncryptionFailed("Reference key cannot be null.");

        try {
            final IvParameterSpec ivParameterSpec = getGuildIvParameter(referenceKey);
            final SecretKey secretkey = getGuildSecretKey(referenceKey);

            return Krypto.encrypt(secretkey, ivParameterSpec, input);
        } catch (final Exception exception) {
            throw new EncryptionFailed(exception.getMessage());
        }
    }

    /**
     * Encrypt string.
     *
     * @param secretKey       the secret key
     * @param ivParameterSpec the iv parameter spec
     * @param input           the input
     * @return the string
     * @throws EncryptionFailed the encryption failed
     */
    public static String encrypt(final SecretKey secretKey, final IvParameterSpec ivParameterSpec, final Object input) throws EncryptionFailed {
        if (!allowNullInput && !safeMode)
            Objects.requireNonNull(input);
        else if (allowNullInput && input == null)
            return null;

        try {
            final Cipher cipher = Cipher.getInstance(AES_METHOD);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

            final byte[] key = cipher.doFinal(input.toString().getBytes());

            return Base64.getEncoder().encodeToString(key);
        } catch (final Exception exception) {
            if (safeMode)
                return input != null ? input.toString() : "";

            throw new EncryptionFailed(exception.getMessage());
        }
    }

    /**
     * Decrypt string.
     *
     * @param referenceKey the reference key
     * @param input        the input
     * @return the string
     * @throws DecryptionFailed the decryption failed
     */
    public static String decrypt(final String referenceKey, final Object input) throws DecryptionFailed {
        if (referenceKey == null)
            throw new DecryptionFailed("Reference key cannot be null.");

        try {
            final IvParameterSpec ivParameterSpec = getGuildIvParameter(referenceKey);
            final SecretKey secretkey = getGuildSecretKey(referenceKey);

            return Krypto.decrypt(secretkey, ivParameterSpec, input);
        } catch (final Exception exception) {
            throw new DecryptionFailed(exception.getMessage());
        }
    }

    /**
     * Decrypt string.
     *
     * @param secretKey       the secret key
     * @param ivParameterSpec the iv parameter spec
     * @param input           the input
     * @return the string
     * @throws DecryptionFailed the decryption failed
     */
    public static String decrypt(final SecretKey secretKey, final IvParameterSpec ivParameterSpec, final Object input) throws DecryptionFailed {
        if (!allowNullInput && !safeMode)
            Objects.requireNonNull(input);
        else if (allowNullInput && input == null)
            return null;

        try {
            final Cipher cipher = Cipher.getInstance(AES_METHOD);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            final byte[] key = cipher.doFinal(Base64.getDecoder().decode(input.toString()));

            return new String(key, StandardCharsets.UTF_8);
        } catch (final Exception exception){
            if (safeMode)
                return input != null ? input.toString() : "";

            throw new DecryptionFailed(exception.getMessage());
        }
    }

    /**
     * Encrypt string.
     *
     * @param input the input
     * @return the string
     * @throws EncryptionFailed the encryption failed
     */
    public String encrypt(final Object input) throws EncryptionFailed {
        return Krypto.encrypt(this.referenceKey, input);
    }

    /**
     * Decrypt string.
     *
     * @param input the input
     * @return the string
     * @throws DecryptionFailed the decryption failed
     */
    public String decrypt(final Object input) throws DecryptionFailed {
        return Krypto.decrypt(this.referenceKey, input);
    }

    /**
     * Encrypt list.
     *
     * @param input the input
     * @return the list
     * @throws EncryptionFailed the encryption failed
     */
    public List<String> encrypt(final List<String> input) throws EncryptionFailed {
        return Krypto.encrypt(this.referenceKey, input);
    }

    /**
     * Decrypt list.
     *
     * @param input the input
     * @return the list
     * @throws DecryptionFailed the decryption failed
     */
    public List<String> decrypt(final List<String> input) throws DecryptionFailed {
        return Krypto.decrypt(this.referenceKey, input);
    }
}
