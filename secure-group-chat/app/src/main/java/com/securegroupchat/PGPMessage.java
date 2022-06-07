package com.securegroupchat;

/**
 * Message class representing PGP-encoded messages
 * 
 * @author Jaron Cohen
 * @author Carl Combrinck
 * @author Bailey Green
 * @version 1.0.0
 */
public class PGPMessage extends Message {
    private byte[] pgpMessage;
    private boolean protocol;

    /**
     * Class constructor
     * @param sender        The message sender
     * @param receiver      The message receiver
     * @param pgpMessage    The PGP-encoded payload
     * @param protocol      Whether the payload should be read as a protocol or text message
     */
    public PGPMessage(String sender, String receiver, byte[] pgpMessage, boolean protocol) {
        super(sender, receiver);
        this.pgpMessage = pgpMessage;
        this.protocol = protocol;
    }

    /**
     * Payload getter
     * @return The byte[] containing the PGP-encoded bytes
     */
    public byte[] getPgpMessage() {
        return pgpMessage;
    }

    /**
     * Protocol getter
     * @return Whether the message is a protocol message
     */
    public boolean getProtocol(){ 
        return protocol; 
    }
}
