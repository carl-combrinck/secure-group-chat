package com.nis.shared;

import java.util.Arrays;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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
     * Class constants
     */
    private final static String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private final static int RSA_KEY_SIZE = 2048;
    private final static String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private final static int AES_KEY_SIZE = 256;
    private final static int AES_IV_SIZE = 128;
    private final static String HASH_ALGORITHM = "SHA-256";
    private final static int SIGNATURE_SIZE = 256;

    /**
     * Empty, private default constructor (cannot instantiate class)
     */
    private PGPUtilities(){
        
    }
    
    /** 
     * Computes a hash of the input bytes
     * 
     * @param bytes The byte[] containing the payload/message bytes
     * @return The byte[] containing the hashed message bytes
     * @throws NoSuchAlgorithmException
     */
    public static byte[] computeHash(byte[] bytes) throws NoSuchAlgorithmException{
        MessageDigest payloadDigest = MessageDigest.getInstance(HASH_ALGORITHM);
        return payloadDigest.digest(bytes);
    }

    
    /** 
     * Signs the hash of a message using a private key
     * 
     * @param bytes The message
     * @param privateKey The private key of the sender
     * @return The signature
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] computeSignature(byte[] bytes, Key privateKey) throws InvalidKeyException, NoSuchAlgorithmException, 
    NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        return encryptWithRSA(computeHash(bytes), privateKey);
    }
    
    /** 
     * Encrypts a byte[] using RSA encryption with the given key
     * 
     * @param bytes
     * @param key
     * @return byte[]
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encryptWithRSA(byte[] bytes, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, 
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher encryptCipher = Cipher.getInstance(RSA_ALGORITHM);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        return encryptCipher.doFinal(bytes);
    }
    
    /** 
     * Decrypts a byte[] using RSA decryption with the given key
     * 
     * @param bytes
     * @param key
     * @return byte[]
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decryptWithRSA(byte[] bytes, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, 
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher decryptCipher = Cipher.getInstance(RSA_ALGORITHM);
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
        return decryptCipher.doFinal(bytes);
    }

    /** 
     * Compresses array of bytes using ZIP compression
     * 
     * @param bytes The byte[] containing the raw message bytes
     * @return A byte[] containing the compressed bytes
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
     * @param bytes The byte[] containing the compressed message bytes
     * @return A byte[] containing the uncompressed bytes
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
    
    /** 
     * Verifies a signature for a given message by comparing the hashed message with 
     * the signature after decrypting with the sender's public key
     * 
     * @param message 
     * @param signature
     * @param publicKey
     * @return Whether the signature is correct 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static boolean verifySignature(byte[] message, byte[] signature, Key publicKey) throws InvalidKeyException, 
    NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        return Arrays.equals(computeHash(message), decryptWithRSA(signature, publicKey));
    }
    
    /** 
     * Concatenates two byte arrays
     * 
     * @param first The first byte array
     * @param second The second byte array
     * @return The result of the concatenation
     * @throws IOException
     */
    public static byte[] concatenate(byte[] first, byte[] second) throws IOException{
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(first);
        outputStream.write(second);
        return outputStream.toByteArray();
    }
    
    /** 
     * Generates a random RSA key pair
     * 
     * @return The random keypair
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException{
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstanceStrong();
        generator.initialize(RSA_KEY_SIZE, random);
        return generator.generateKeyPair();
    }
    
    /** 
     * Generates a random AES key
     * 
     * @return The random key
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException{
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        SecureRandom random = SecureRandom.getInstanceStrong();
        generator.init(AES_KEY_SIZE, random);
        return generator.generateKey();
    }
    
    /** 
     * Generates a random initialization vector for AES encryption
     * 
     * @return The random initialization vector
     * @throws NoSuchAlgorithmException
     */
    public static IvParameterSpec generateIV() throws NoSuchAlgorithmException{
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] initializationVector = new byte[AES_IV_SIZE/8];
        random.nextBytes(initializationVector);
        return new IvParameterSpec(initializationVector);
    }

    /** 
     * Encrypts a message using AES encryption and the provided key and iv
     * 
     * @param bytes The bytes of the message to encrypt
     * @param key The key
     * @param iv The initialization vector
     * @return The encrypted message bytes
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] encryptWithAES(byte[] bytes, SecretKey key, IvParameterSpec iv) throws InvalidKeyException, 
    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, 
    NoSuchAlgorithmException, NoSuchPaddingException{
        Cipher encryptCipher = Cipher.getInstance(AES_ALGORITHM);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return encryptCipher.doFinal(bytes);
    }

    /** 
     * Decrypts a message using AES decryption and the provided key and iv
     * 
     * @param bytes The bytes of the message to decrypt
     * @param key The key
     * @param iv The initialization vector
     * @return The decrypted message bytes
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] decryptWithAES(byte[] bytes, SecretKey key, IvParameterSpec iv) throws InvalidKeyException, 
    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, 
    NoSuchAlgorithmException, NoSuchPaddingException{
        Cipher decryptCipher = Cipher.getInstance(AES_ALGORITHM);
        decryptCipher.init(Cipher.DECRYPT_MODE, key, iv);
        return decryptCipher.doFinal(bytes);
    }
}