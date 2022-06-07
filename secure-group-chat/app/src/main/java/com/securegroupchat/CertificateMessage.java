package com.securegroupchat;

import java.security.cert.X509Certificate;

/**
 * Message for exchanging client certificates
 * 
 * @author Jaron Cohen
 * @author Carl Combrinck
 * @author Bailey Green
 * @version 1.0.0
 */
public class CertificateMessage extends Message {
    private X509Certificate certificate;
    private boolean reply;

    /**
     * Constructor for CertificateMessage
     * @param sender        The sender of the certificate
     * @param receiver      The recipient
     * @param certificate   The CA-signed X.509 certificate
     * @param reply         Whether this is a response to a received certificate
     */
    public CertificateMessage(String sender, String receiver, X509Certificate certificate, boolean reply) {
        super(sender, receiver);
        this.certificate = certificate;
        this.reply = reply;
    }

    /**
     * Certificate getter
     * @return The X.509 certificate payload
     */
    public X509Certificate getCertificate() {
        return this.certificate;
    }

    /**
     * Reply getter
     * @return Whether this message is a reply
     */
    public boolean getReply() {
        return this.reply;
    }
}
