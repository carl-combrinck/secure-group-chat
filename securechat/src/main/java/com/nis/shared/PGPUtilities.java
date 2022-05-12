package com.nis.shared;

import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * PGPUtilities is a class containing all the functionality necessary for implementing a PGP-based communication session between two hosts.
 * 
 * @author Carl Combrinck
 * @author Bailey Green
 * @author Jaron Cohen
 * @version 1.0.0
 */
public class PGPUtilities{

    /**
     * Empty, private default constructor (cannot instantiate class)
     */
    private PGPUtilities(){

    }

    /** 
     * Compresses array of bytes using ZIP compression
     * 
     * @param bytes
     * @return byte[]
     * @throws IOException
     */
    public static byte[] compress(byte[] bytes) throws IOException {
        // Create output streams
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(outputStream);
        try
        {
            // Write bytes to deflater stream
            deflaterOutputStream.write(bytes); 
            deflaterOutputStream.finish();
        }
        finally
        {
            outputStream.close();
            deflaterOutputStream.close();
        }
        return outputStream.toByteArray();    
    }
 
    
    /** 
     * Decompresses compressed array of bytes using ZIP decompression
     * 
     * @param bytes
     * @return byte[]
     * @throws IOException
     */
    public static byte[] decompress(byte[] bytes) throws IOException {
        // Create output streams
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(outputStream);
        try
        {
            // Write bytes to inflater stream
            inflaterOutputStream.write(bytes); 
            inflaterOutputStream.finish();
        }
        finally
        {
            outputStream.close();
            inflaterOutputStream.close();
        }  
        return outputStream.toByteArray();    
    }

    
}