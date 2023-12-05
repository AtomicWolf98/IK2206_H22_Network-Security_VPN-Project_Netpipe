import java.io.InputStream;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.PublicKey;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */

public class HandshakeCertificate {
    public X509Certificate Certificate;
    public byte[] Byte;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */

    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        this.Certificate = (X509Certificate) certificateFactory.generateCertificate(instream);
    }
    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certbytes);
        this.Certificate = (X509Certificate)certificateFactory.generateCertificate(in);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */

    public byte[] getBytes() throws CertificateEncodingException{
        return  this.Certificate.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return this.Certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        X509Certificate CACertificate = cacert.getCertificate();
        this.Certificate.verify(CACertificate.getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        X500Principal findCNfunction = this.Certificate.getSubjectX500Principal();
        try {
            LdapName ldapName = new LdapName(findCNfunction.getName());
            for (Rdn random : ldapName.getRdns()) {
                if (random.getType().equalsIgnoreCase("cn")) {
                    return random.getValue().toString();
                }
            }
            return findCNfunction.getName();
        } catch (NamingException ex) {
            return findCNfunction.getName();
        }
    }

    /*
     * return email address of subject
     */
    public String getEmail() {
        X500Principal findEmailfunction = this.Certificate.getSubjectX500Principal();
        try {
            LdapName ldapName = new LdapName(findEmailfunction.toString());
            for (Rdn ramdon : ldapName.getRdns()) {
                if (ramdon.getType().equalsIgnoreCase("emailaddress")) {
                    return ramdon.getValue().toString();
                }
            }
            return findEmailfunction.toString();
        } catch (NamingException ex) {
            return findEmailfunction.toString();
        }
    }
}
