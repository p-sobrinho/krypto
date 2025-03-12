package me.koji.github.Exceptions;

public class DecryptionFailed extends RuntimeException {
    private final Exception originalException;

    public DecryptionFailed() {
        super("Encryption failed.");
        this.originalException = null;
    }

    public DecryptionFailed(final String message) {
        super(message);
        this.originalException = null;
    }

    public <T extends Exception> DecryptionFailed(final String message, final T originalException) {
        super(message);
        this.originalException = originalException;
    }
}