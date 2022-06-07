package com.securegroupchat;

import java.util.logging.Level;

/**
 * Class containing custom logging levels
 *
 * @author Jaron Cohen
 * @author Carl Combrinck
 * @author Bailey Green
 * @version 1.0.0
 */
public class LoggingLevel extends Level{
    // DEBUG Level
    public static final Level DEBUG = new LoggingLevel("DEBUG", Level.INFO.intValue());
    // INFO Level
    public static final Level INFO = new LoggingLevel("INFO", Level.WARNING.intValue());

    /**
     * LoggingLevel constructor
     * 
     * @param name The name of the logging level
     * @param level The level's integer value
     */
    public LoggingLevel(String name, int level) {
        super(name, level);
    }
}