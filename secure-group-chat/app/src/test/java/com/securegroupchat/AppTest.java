package com.securegroupchat;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;

import com.securegroupchat.PGPUtilities;

/**
 * Unit tests for Secure Group Chat.
 */
public class AppTest {
    
    //Test string containing all 'standard' characters
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
    public void testCompression() throws IOException {
        byte[] raw = TEST_STRING.getBytes();
        // Compress then decompress using ZIP
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
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        KeyPair pair = PGPUtilities.generateRSAKeyPair();
        // Encrypt with PR and Decrypt with PU
        byte[] raw = TEST_STRING.getBytes();
        byte[] encrypted = PGPUtilities.encryptWithRSA(raw, pair.getPrivate());
        byte[] decrypted = PGPUtilities.decryptWithRSA(encrypted, pair.getPublic());
        assertTrue(Arrays.equals(decrypted, raw));
        // Encrypt with PU and Decrypt with PR
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
            IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        SecretKey key = PGPUtilities.generateAESKey();
        IvParameterSpec iv = PGPUtilities.generateIV();
        // Encrypt and decrypt with AES
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
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        KeyPair pair = PGPUtilities.generateRSAKeyPair();
        // Generate and verify signature
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
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        // Concatenate random split of message bytes
        int randomIndex = (int) (Math.random() * (TEST_STRING.length() + 1));
        byte[] first = TEST_STRING.substring(0, randomIndex).getBytes();
        byte[] second = TEST_STRING.substring(randomIndex).getBytes();
        assertTrue(Arrays.equals(PGPUtilities.concatenate(first, second), TEST_STRING.getBytes()));
    }

    /**
     * Tests base 64 encoding and decoding
     */
    @Test
    public void testBase64() {
        // Base 64 encode and decode
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
            IOException {
        KeyPair senderPair = PGPUtilities.generateRSAKeyPair();
        KeyPair receiverPair = PGPUtilities.generateRSAKeyPair();
        // Encode with PGP then decode with PGP
        byte[] encodedMessage = PGPUtilities.encode(TEST_STRING.getBytes(), senderPair.getPrivate(),
                receiverPair.getPublic(), logger);
        byte[] decodedMessage = PGPUtilities.decode(encodedMessage, receiverPair.getPrivate(), senderPair.getPublic(),
                logger);
        assertTrue(Arrays.equals(TEST_STRING.getBytes(), decodedMessage));
    }

    /**
     * Tests message corruption or tampering results in different signatures
     * 
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Test
    public void testMessageSignatureCorruption() throws IOException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        KeyPair pair = PGPUtilities.generateRSAKeyPair();
        // Message signature
        byte[] raw = TEST_STRING.getBytes();
        byte[] signature = PGPUtilities.computeSignature(raw, pair.getPrivate());
        // Corrupted raw message
        String corruptedStr = TEST_STRING.substring(2);
        byte[] corrupted = corruptedStr.getBytes();
        // Test for signature verification failure
        boolean valid = false;
        try {
            valid = PGPUtilities.verifySignature(corrupted, signature, pair.getPublic());
        } catch (Exception e) {
            valid = false;
        }
        assertFalse(valid);
    }

    /**
     * Tests certificate verification fails when certificate from untrusted CA
     * 
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws Exception
     */
    @Test()
    public void testUntrustedCertificate() throws NoSuchAlgorithmException, CertificateException, InvalidKeyException,
            NoSuchProviderException, SignatureException, Exception {
        KeyPair untrustedCAKeyPair = PGPUtilities.generateRSAKeyPair();
        KeyPair trustedCAKeyPair = PGPUtilities.generateRSAKeyPair();
        KeyPair userKeyPair = PGPUtilities.generateRSAKeyPair();
        // Generate certificate using untrusted private key
        X509Certificate untrustedCertificate = CertificateAuthority.generateCertificate("SUBJ", userKeyPair.getPublic(),
                untrustedCAKeyPair.getPrivate());
        // Test for error on certificate verification
        assertThrows(Exception.class, () -> {
            untrustedCertificate.verify(trustedCAKeyPair.getPublic());
        });
    }

    /**
     * Tests if secret key is decrypted by a different key pair than
     * what it was encrypted with (representing incorrect recipient)
     * 
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Test()
    public void testIncorrectKeyPair() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] secretKey = PGPUtilities.generateAESKey().getEncoded();
        KeyPair correctKeyPair = PGPUtilities.generateRSAKeyPair();
        KeyPair incorrectKeyPair = PGPUtilities.generateRSAKeyPair();
        // Correctly encrypted secret key
        byte[] encryptedSecretKey = PGPUtilities.encryptWithRSA(secretKey, correctKeyPair.getPublic());
        // Decrypt key with incorrect pair
        boolean correct = true;
        try{
            byte[] decryptedSecretKey = PGPUtilities.decryptWithRSA(encryptedSecretKey, incorrectKeyPair.getPrivate());
            correct = Arrays.equals(secretKey,decryptedSecretKey);
        }catch(Exception e){
            correct = false;
        }
        assertFalse(correct);
    }

    /**
     * Tests if corruption of encoded PGP message is correctly detected (i.e. while being transmitted between sender and receiver)
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     * @throws InvalidKeyException
     */
    @Test()
    public void testPGPMessageCorruption() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, 
    IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException, SignatureException {
        KeyPair pairSender = PGPUtilities.generateRSAKeyPair();
        KeyPair pairReceiver = PGPUtilities.generateRSAKeyPair();
        // Generate encoded message
        byte[] plaintext = TEST_STRING.getBytes();
        byte[] ciphertext = PGPUtilities.encode(plaintext,pairSender.getPrivate(),pairReceiver.getPublic(),logger);
        Random generator = new Random();
        int randomByteIndex = generator.nextInt(ciphertext.length);
        // Modify random encoded message byte
        byte[] corruptedCiphertext = Arrays.copyOf(ciphertext,ciphertext.length);
        corruptedCiphertext[randomByteIndex] += 1;
        // Decode corrupted message
        boolean correct = true;
        try{
            byte[] corruptedPlaintext = PGPUtilities.decode(corruptedCiphertext,pairReceiver.getPrivate(),pairSender.getPublic(),logger);
            correct = Arrays.equals(plaintext,corruptedPlaintext);
        }catch(Exception e){
            correct = false;
        }
        assertFalse(correct);
    }
}
