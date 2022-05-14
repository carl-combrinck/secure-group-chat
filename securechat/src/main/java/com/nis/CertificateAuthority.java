package com.nis;

import com.nis.shared.KeyUtilities;

import java.io.FileOutputStream;
import java.security.*;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import java.util.*;

public class CertificateAuthority {
    private static final String KEYSTORENAME = "nis_group_chat_PKCS12";
    private static final char[] KEYSTOREPASSWORD = "nis2020".toCharArray();

    public static void main(String[] args) throws Exception {
            KeyPair CAKeyPair = KeyUtilities.generateRSAKeys();
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
}
