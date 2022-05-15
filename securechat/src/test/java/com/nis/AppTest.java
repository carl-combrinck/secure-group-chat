package com.nis;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;

import org.junit.Test;

import com.nis.shared.PGPUtilities;

/**
 * Unit tests for Secure Group Chat.
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
        KeyPair pair = PGPUtilities.generateRSAKeyPair();

        byte[] raw = TEST_STRING.getBytes();
        byte[] encrypted = PGPUtilities.encryptWithRSA(raw, pair.getPrivate());
        byte[] decrypted = PGPUtilities.decryptWithRSA(encrypted, pair.getPublic());
        assertTrue((new String(decrypted)).equals(TEST_STRING));

        encrypted = PGPUtilities.encryptWithRSA(raw, pair.getPublic());
        decrypted = PGPUtilities.decryptWithRSA(encrypted, pair.getPrivate());
        assertTrue((new String(decrypted)).equals(TEST_STRING));
    }

    @Test
    public void testAES() throws InvalidKeyException, InvalidAlgorithmParameterException, 
    IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException 
    {
        SecretKey key = PGPUtilities.generateAESKey();
        IvParameterSpec iv = PGPUtilities.generateIV();

        byte[] raw = TEST_STRING.getBytes();
        byte[] encrypted = PGPUtilities.encryptWithAES(raw, key, iv);
        byte[] decrypted = PGPUtilities.decryptWithAES(encrypted, key, iv);
        assertTrue((new String(decrypted)).equals(TEST_STRING));
    }

    @Test
    public void testSignature() throws IOException, NoSuchAlgorithmException, InvalidKeyException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        KeyPair pair = PGPUtilities.generateRSAKeyPair();

        byte[] raw = TEST_STRING.getBytes();
        byte[] signature = PGPUtilities.computeSignature(raw, pair.getPrivate());
        assertTrue(PGPUtilities.verifySignature(raw, signature, pair.getPublic()));
    }

    @Test
    public void testConcatenation() throws IOException, NoSuchAlgorithmException, InvalidKeyException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] first = TEST_STRING.substring(0, 30).getBytes();
        byte[] second = TEST_STRING.substring(30).getBytes();
        assertTrue((new String(PGPUtilities.concatenate(first, second))).equals(TEST_STRING));
    }

}
