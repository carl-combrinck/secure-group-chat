package com.securegroupchat;

public class CommandMessage extends Message {

    private String command;

    public CommandMessage(String sender, String receiver, String command) {
        super(sender, receiver);
        this.command = command;
    }

    public String getCommand() {
        return command;
    }

}