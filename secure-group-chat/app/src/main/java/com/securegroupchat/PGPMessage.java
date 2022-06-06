package com.securegroupchat;

public class PGPMessage extends Message {
    private byte[] pgpMessage;
    private boolean protocol;

    public PGPMessage(String sender, String receiver, byte[] pgpMessage, boolean protocol) {
        super(sender, receiver);
        this.pgpMessage = pgpMessage;
        this.protocol = protocol;
    }

    public byte[] getPgpMessage() {
        return pgpMessage;
    }

    public boolean getProtocol(){ return protocol; }

}
