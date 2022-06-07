package com.securegroupchat;

/**
 * Message for exchanging commands
 * 
 * @author Jaron Cohen
 * @author Carl Combrinck
 * @author Bailey Green
 * @version 1.0.0
 */
public class CommandMessage extends Message {

    private String command;

    /**
     * Constructor
     * @param sender    Message sender
     * @param receiver  Message recipient
     * @param command   Command being issued
     */
    public CommandMessage(String sender, String receiver, String command) {
        super(sender, receiver);
        this.command = command;
    }

    /**
     * Command getter
     * @return The command string
     */
    public String getCommand() {
        return command;
    }

}