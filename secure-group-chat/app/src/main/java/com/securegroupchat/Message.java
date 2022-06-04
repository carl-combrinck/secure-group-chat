package com.securegroupchat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

abstract class Message implements Serializable {

    private String sender;
    private String receiver;

    public Message(String sender, String receiver) {
        this.sender = sender;
        this.receiver = receiver;
    }

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

    public String getSender() {
        return sender;
    }

    public String getReceiver() {
        return receiver;
    }
}