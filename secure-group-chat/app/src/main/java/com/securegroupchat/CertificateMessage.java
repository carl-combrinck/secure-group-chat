package com.securegroupchat;

import java.security.cert.X509Certificate;

public class CertificateMessage extends Message {
    private X509Certificate certificate;
    private boolean reply;

    public CertificateMessage(String sender, String receiver, X509Certificate certificate, boolean reply) {
        super(sender, receiver);
        this.certificate = certificate;
        this.reply = reply;
    }

    public X509Certificate getCertificate() {
        return this.certificate;
    }
    public boolean getReply() {return this.reply;}
}
