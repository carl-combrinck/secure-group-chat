package com.securegroupchat;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

import com.securegroupchat.PGPUtilities;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.cert.*;

import java.math.BigInteger;

import java.util.*;

/**
 * CertificateAuthority is a class that generates a self-signed root X.509 certificate
 * stored in a PKCS12 KeyStore. Additionally, it provides functionality to generate and sign
 * X.509 certificates for Clients with its private key.
 *
 * @author Jaron Cohen
 * @author Carl Combrinck
 * @author Bailey Green
 * @version 1.0.0
 */
public class CertificateAuthority {

    /**
     * Class constants
     */
    private static final String KEYSTORENAME = "nis_group_chat_PKCS12";
    private static final char[] KEYSTOREPASSWORD = "nis2020".toCharArray();
    private KeyPair CAKeyPair;

    /**
     * Class constructor - retrieves CA KeyPair from KeyStore on disk and stores in memory
     * @throws KeyStoreException
     * @throws UnrecoverableEntryException
     * @throws NoSuchAlgorithmException
     */
    public CertificateAuthority() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        KeyStore CAKeyStore = KeyStore.getInstance("pkcs12");

        try (FileInputStream fis = new FileInputStream(KEYSTORENAME)) {
            CAKeyStore.load(fis, KEYSTOREPASSWORD);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }

        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(KEYSTOREPASSWORD);
        KeyStore.PrivateKeyEntry CAentry = (KeyStore.PrivateKeyEntry) CAKeyStore.getEntry("CA_cert",protParam);
        PublicKey CAPublic = CAentry.getCertificate().getPublicKey();
        PrivateKey CAPrivate = CAentry.getPrivateKey();

        this.CAKeyPair = new KeyPair(CAPublic,CAPrivate);
    }

    public PublicKey getPublicKey(){
        return this.CAKeyPair.getPublic();
    }

    /**
     * Creates new KeyStore, generates CA KeyPair and stores self-signed root X.509 certificate in new KeyStore on disk.
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
            KeyPair CAKeyPair = PGPUtilities.generateRSAKeyPair();
            X509Certificate CArootCertificate = generateCertificate("CA", CAKeyPair.getPublic(), CAKeyPair.getPrivate());
            KeyStore CAKeyStore = KeyStore.getInstance("pkcs12");
            CAKeyStore.load(null,KEYSTOREPASSWORD);
            KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(CAKeyPair.getPrivate(),new X509Certificate[]{CArootCertificate});
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(KEYSTOREPASSWORD);
            CAKeyStore.setEntry("CA_cert",entry,protParam);

            //Save the keystore to disk
            try (FileOutputStream fos = new FileOutputStream(KEYSTORENAME)) {
                CAKeyStore.store(fos, KEYSTOREPASSWORD);
            }
    }

    /**
     * Generates a signed X.509 certificate using SHA256WithRSAEncryption by means of the Bouncy Castle Library.
     * @param subj          Subject of the certificate
     * @param publicKey     Public key associated with certificate
     * @param caPrivateKey  Private key of the Certificate Authority for signing
     * @return X509Certificate
     * @throws Exception
     */
    public static X509Certificate generateCertificate(String subj, PublicKey publicKey, PrivateKey caPrivateKey) throws Exception{

        X500Name issuer = new X500Name("CN=CA, L=Cape Town, C=ZA ");
        X500Name subject = new X500Name("CN=" + subj);

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        Date notBefore = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, 12);
        Date notAfter = calendar.getTime();

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore,
                notAfter, subject, publicKey);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(new BouncyCastleProvider())
                .build(caPrivateKey);
        X509CertificateHolder certificateHolder = certificateBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certificateHolder);
    }

    /**
     * Method to generate signed X.509 certificates for Clients
     * @param subject       Subject of the certificate (Client's identifier)
     * @param publicKey     Public key associated with certificate (Client's Public Key)
     * @return X509Certificate
     * @throws Exception
     */
    public X509Certificate generateSignedCertificate(String subject, PublicKey publicKey) throws Exception {
        return generateCertificate(subject,publicKey,CAKeyPair.getPrivate());
    }

}
