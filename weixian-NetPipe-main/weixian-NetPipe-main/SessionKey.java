import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
    public SecretKey NewKey;

    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
        KeyGen.init(keylength);
        NewKey = KeyGen.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        NewKey = new SecretKeySpec(keybytes,"AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return NewKey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return NewKey.getEncoded();
    }
}

