package com.securegroupchat;

import java.security.cert.X509Certificate;

public class CertificateMessage extends Message {
    private X509Certificate certificate;

    public CertificateMessage(String sender, String receiver, X509Certificate certificate) {
        super(sender, receiver);
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }
}
