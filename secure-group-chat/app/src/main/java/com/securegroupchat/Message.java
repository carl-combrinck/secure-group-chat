package com.securegroupchat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Abstract class representing all messages transmitted using the application
 * 
 * @author Jaron Cohen
 * @author Carl Combrinck
 * @author Bailey Green
 * @version 1.0.0
 */
abstract class Message implements Serializable {

    private String sender;
    private String receiver;

    /**
     * Constructor
     * @param sender    The sender of the message
     * @param receiver  The recipient of the message
     */
    public Message(String sender, String receiver) {
        this.sender = sender;
        this.receiver = receiver;
    }

    /**
     * Converts object into byte array for transmission
     * @param message The message object to serialize
     * @return The byte array representing the message
     */
    public static byte[] serializeMessage(Message message) {
        ByteArrayOutputStream byteArrayOS = new ByteArrayOutputStream();
        ObjectOutputStream objectOS;
        try {
            objectOS = new ObjectOutputStream(byteArrayOS);
            objectOS.writeObject(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return byteArrayOS.toByteArray();
    }

    /**
     * Converts serialized message into message object
     * @param message The message byte[]
     * @return The message object
     */
    public static Message deserializeMessage(byte[] message) {
        ByteArrayInputStream byteArrayIS = new ByteArrayInputStream(message);
        ObjectInputStream objectIS;
        Message m = null;
        try {
            objectIS = new ObjectInputStream(byteArrayIS);
            m = (Message) objectIS.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return m;
    }

    /**
     * Sender getter
     * @return The sender
     */
    public String getSender() {
        return sender;
    }

    /**
     * Receiver getter
     * @return The receiver
     */
    public String getReceiver() {
        return receiver;
    }
}