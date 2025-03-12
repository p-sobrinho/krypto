package me.koji.github.Exceptions;

public class EncryptionFailed extends RuntimeException {
    private final Exception originalException;

    public EncryptionFailed() {
        super("Encryption failed.");
        this.originalException = null;
    }

    public EncryptionFailed(final String message) {
        super(message);
        this.originalException = null;
    }

    public <T extends Exception> EncryptionFailed(final String message, final T originalException) {
        super(message);
        this.originalException = originalException;
    }
}