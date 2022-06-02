package com.nis;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.logging.Logger;

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
    /**
     * Test string containing all 'standard' characters
     */
    private final String TEST_STRING = "0123456789" +
                            "abcdefghijklmnopqrstuvwxyz" +
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                            ".,/;\"'\\{}[]-_=+?!@#$%^&*()`~<>|" +
                            "\n\t\b\f\r";
    private final static Logger logger = Logger.getLogger(AppTest.class.getName());
    
    /** 
     * Tests compression and decompression using PGPUtilities 
     * zip-based implementation
     * 
     * @throws IOException
     */
    @Test
    public void testCompression() throws IOException
    {
        byte[] raw = TEST_STRING.getBytes();
        byte[] compressed = PGPUtilities.compress(raw);
        byte[] uncompressed = PGPUtilities.decompress(compressed);
        assertTrue(Arrays.equals(raw, uncompressed));
    }

    /** 
     * Tests RSA encryption and decryption
     * 
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Test
    public void testRSA() throws IOException, NoSuchAlgorithmException, InvalidKeyException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        KeyPair pair = PGPUtilities.generateRSAKeyPair();

        byte[] raw = TEST_STRING.getBytes();
        byte[] encrypted = PGPUtilities.encryptWithRSA(raw, pair.getPrivate());
        byte[] decrypted = PGPUtilities.decryptWithRSA(encrypted, pair.getPublic());
        assertTrue(Arrays.equals(decrypted, raw));

        encrypted = PGPUtilities.encryptWithRSA(raw, pair.getPublic());
        decrypted = PGPUtilities.decryptWithRSA(encrypted, pair.getPrivate());
        assertTrue(Arrays.equals(decrypted, raw));
    }

    /** 
     * Tests AES encryption and decryption
     * 
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    @Test
    public void testAES() throws InvalidKeyException, InvalidAlgorithmParameterException, 
    IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException 
    {
        SecretKey key = PGPUtilities.generateAESKey();
        IvParameterSpec iv = PGPUtilities.generateIV();

        byte[] raw = TEST_STRING.getBytes();
        byte[] encrypted = PGPUtilities.encryptWithAES(raw, key, iv);
        byte[] decrypted = PGPUtilities.decryptWithAES(encrypted, key, iv);
        assertTrue(Arrays.equals(decrypted, raw));
    }
    
    /** 
     * Tests signature generation and verification
     * 
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Test
    public void testSignature() throws IOException, NoSuchAlgorithmException, InvalidKeyException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        KeyPair pair = PGPUtilities.generateRSAKeyPair();

        byte[] raw = TEST_STRING.getBytes();
        byte[] signature = PGPUtilities.computeSignature(raw, pair.getPrivate());
        assertTrue(PGPUtilities.verifySignature(raw, signature, pair.getPublic()));
    }

    /** 
     * Tests byte array concatenation
     * 
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Test
    public void testConcatenation() throws IOException, NoSuchAlgorithmException, InvalidKeyException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        int randomIndex = (int)(Math.random()*(TEST_STRING.length()+1));
        byte[] first = TEST_STRING.substring(0, randomIndex).getBytes();
        byte[] second = TEST_STRING.substring(randomIndex).getBytes();
        assertTrue(Arrays.equals(PGPUtilities.concatenate(first, second), TEST_STRING.getBytes()));
    }

    /**
     * Tests base 64 encoding and decoding
     */
    @Test
    public void testBase64() 
    {
        byte[] encoded = PGPUtilities.r64Encode(TEST_STRING.getBytes());
        byte[] decoded = PGPUtilities.r64Decode(encoded);
        assertTrue(Arrays.equals(decoded, TEST_STRING.getBytes()));
    }

    /** 
     * Tests PGP encode and decode pipelines
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws SignatureException
     * @throws IOException
     */
    @Test
    public void testPGP() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, 
    IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException, 
    IOException
    {
        KeyPair senderPair = PGPUtilities.generateRSAKeyPair();
        KeyPair receiverPair = PGPUtilities.generateRSAKeyPair();
        byte[] encodedMessage = PGPUtilities.encode(TEST_STRING.getBytes(), senderPair.getPrivate(), receiverPair.getPublic(), logger);
        byte[] decodedMessage = PGPUtilities.decode(encodedMessage, receiverPair.getPrivate(), senderPair.getPublic(), logger);
        assertTrue(Arrays.equals(TEST_STRING.getBytes(), decodedMessage));
    }

}
