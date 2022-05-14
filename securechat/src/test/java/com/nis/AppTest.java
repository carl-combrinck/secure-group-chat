package com.nis;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.Test;

import com.nis.shared.PGPUtilities;

/**
 * Unit test for simple App.
 */
public class AppTest 
{

    private final String TEST_STRING = "0123456789" +
                            "abcdefghijklmnopqrstuvwxyz" +
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                            ".,/;\"'\\{}[]-_=+?!@#$%^&*()`~";

    @Test
    public void testCompression() throws IOException
    {
        byte[] raw = TEST_STRING.getBytes();
        byte[] compressed = PGPUtilities.compress(raw);
        byte[] uncompressed = PGPUtilities.decompress(compressed);
        assertTrue((new String(uncompressed)).equals(TEST_STRING));
    }
}
