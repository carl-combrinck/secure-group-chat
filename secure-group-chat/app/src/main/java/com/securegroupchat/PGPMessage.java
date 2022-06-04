package com.securegroupchat;

public class PGPMessage extends Message {

    private byte[] pgpMessage;

    public PGPMessage(String sender, String receiver, byte[] pgpMessage) {
        super(sender, receiver);
        this.pgpMessage = pgpMessage;
    }

    public byte[] getPgpMessage() {
        return pgpMessage;
    }

}
