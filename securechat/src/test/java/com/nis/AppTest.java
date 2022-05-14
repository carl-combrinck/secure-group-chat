package com.nis;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidKeyException;
import java.security.KeyPair;

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

    @Test
    public void testRSA() throws IOException, NoSuchAlgorithmException, InvalidKeyException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        byte[] raw = TEST_STRING.getBytes();
        byte[] encrypted = PGPUtilities.encryptWithRSA(raw, pair.getPrivate());
        byte[] decrypted = PGPUtilities.decryptWithRSA(encrypted, pair.getPublic());
        assertTrue((new String(decrypted)).equals(TEST_STRING));

        encrypted = PGPUtilities.encryptWithRSA(raw, pair.getPublic());
        decrypted = PGPUtilities.decryptWithRSA(encrypted, pair.getPrivate());
        assertTrue((new String(decrypted)).equals(TEST_STRING));
    }

}
