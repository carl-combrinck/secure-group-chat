package com.nis.shared;

import java.util.Arrays;
import java.util.logging.Logger;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
import java.security.SignatureException;

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
    private final static int SESSION_DATA_BYTES = RSA_KEY_SIZE/8;
    private final static String HASH_ALGORITHM = "SHA-256";
    private final static int SIGNATURE_SIZE = 256;

    /**
     * Empty, private default constructor (cannot instantiate class)
     */
    private PGPUtilities(){
        
    }
    
    /** 
     * Computes a SHA256 hash of the input bytes
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
     * Signs the hash of a message using a private key with RSA encryption
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
    public static byte[] encryptWithRSA(final byte[] bytes, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, 
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
     * Verifies signature for a given message by comparing the hashed message with 
     * the signature after decrypting with the sender's public key using RSA
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
        generator.initialize(RSA_KEY_SIZE);
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
        generator.init(AES_KEY_SIZE);
        return generator.generateKey();
    }
    
    /** 
     * Generates a random 16 byte initialization vector for AES encryption
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
     * Encrypts a message using AES encryption with the provided key and iv
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
     * Decrypts a message using AES decryption with the provided key and iv
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
    
    /** 
     * Returns a subarray of a given byte array
     * 
     * @param bytes The byte[] to extract from
     * @param start The starting index (inclusive)
     * @param end The ending index (exclusive)
     * @return The subarray
     */
    public static byte[] slice(byte[] bytes, int start, int end){
        return Arrays.copyOfRange(bytes, start, end);
    }
    
    /** 
     * Logs PGP encoding information
     * 
     * @param logger The logger
     * @param raw The raw message
     * @param sign The message signature
     * @param zip The compressed signed message
     * @param sesh The session data
     * @param emsg The encrypted message
     * @param esesh The encrypted session data
     * @param pgp The PGP message
     */
    private static void logEncode(Logger logger, byte[] raw, byte[] sign, byte[] zip, byte[] sesh, byte[] emsg, byte[] esesh, byte[] pgp){
        final String line = "\n--------------------------\n";
        String log = "Encoding message...\n" +
        "RAW MESSAGE:" + line + "%s" + line +
        "SIGNATURE:" + line+ "%s" + line +
        "COMPRESSED:" + line + "%s" + line +
        "SESSION KEY AND IV:" + line + "%s" + line +
        "ENCRYPTED MESSAGE:" + line + "%s" + line +
        "ENCRYPTED SESSION:" + line + "%s" + line +
        "PGP MESSAGE:" + line + "%s" + line;
        logger.info(String.format(log, new String(raw), new String(sign), new String(zip), 
            new String(sesh), new String(emsg), new String(esesh), new String(pgp)));
    }
    
    /** 
     * Logs PGP decoding information
     * 
     * @param logger The logger
     * @param raw The raw message
     * @param sign The message signature
     * @param zip The compressed signed message
     * @param sesh The session data
     * @param emsg The encrypted message
     * @param esesh The encrypted session data
     * @param pgp The PGP message
     */
    private static void logDecode(Logger logger, byte[] raw, byte[] sign, byte[] zip, byte[] sesh, byte[] emsg, byte[] esesh, byte[] pgp){
        final String line = "\n--------------------------\n";
        String log = "Decoding message...\n" +
        "PGP MESSAGE:" + line + "%s" + line +
        "ENCRYPTED SESSION:" + line + "%s" + line +
        "ENCRYPTED MESSAGE:" + line + "%s" + line +
        "SESSION KEY AND IV:" + line + "%s" + line +
        "COMPRESSED:" + line + "%s" + line +
        "SIGNATURE:" + line+ "%s" + line +
        "RAW MESSAGE:" + line + "%s" + line;
        logger.info(String.format(log, new String(pgp), new String(esesh), new String(emsg), 
        new String(sesh), new String(zip), new String(sign), new String(raw)));
    }

    /** 
     * Encodes a raw message using PGP-based techniques from tranmission from the sender to a particular recipient
     * 
     * @param message The raw message
     * @param senderPrivateKey The private key of the sender
     * @param receiverPublicKey The public key of the receiver
     * @param logger The logger
     * @return The encoded PGP message
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] encode(byte[] message, Key senderPrivateKey, Key receiverPublicKey, Logger logger) throws InvalidKeyException, 
    NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, 
    InvalidAlgorithmParameterException{
        // Sign and compress message
        byte[] signature = computeSignature(message, senderPrivateKey);
        byte[] compressedSignedMessage = compress(concatenate(signature, message));
        // Generate session key and iv
        SecretKey sessionKey = generateAESKey();
        IvParameterSpec sessionIV = generateIV();
        byte[] sessionData = concatenate(sessionIV.getIV(), sessionKey.getEncoded());
        // Encrypt message with session key and iv
        byte[] encryptedMessage = encryptWithAES(compressedSignedMessage, sessionKey, sessionIV);
        // Encrypt session data with receiver public key
        byte[] encryptedSessionData = encryptWithRSA(sessionData, receiverPublicKey);
        byte[] encodedMessage = concatenate(encryptedSessionData, encryptedMessage);
        // Logging
        logEncode(logger, message, signature, compressedSignedMessage, sessionData, encryptedMessage, encryptedSessionData, encodedMessage);
        return encodedMessage;
    }

    /** 
     * Decodes a PGP message received from a particular sender
     * 
     * @param encodedMessage The encoded PGP message
     * @param receiverPrivateKey The private key of the recipient
     * @param senderPublicKey The public key of the sender
     * @param logger The logger
     * @return The raw, decoded message
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws IOException
     * @throws SignatureException
     */
    public static byte[] decode(byte[] encodedMessage, Key receiverPrivateKey, Key senderPublicKey, Logger logger) throws InvalidKeyException, 
    NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, 
    IOException, SignatureException{
        // Extract encrypted session and message data
        byte[] encryptedSessionData = slice(encodedMessage, 0, SESSION_DATA_BYTES);
        byte[] encryptedMessage = slice(encodedMessage, SESSION_DATA_BYTES, encodedMessage.length);
        // Decrypt encrypted session data with RSA to obtain session key and IV
        byte[] sessionData = decryptWithRSA(encryptedSessionData, receiverPrivateKey);
        SecretKey sessionKey = new SecretKeySpec(sessionData, AES_IV_SIZE/8, AES_KEY_SIZE/8, "AES");
        IvParameterSpec sessionIV = new IvParameterSpec(slice(sessionData, 0, AES_IV_SIZE/8));
        // Decrypt encryted message with AES to obtain compressed signed message
        byte[] compressedSignedMessage = decryptWithAES(encryptedMessage, sessionKey, sessionIV);
        // Decompress
        byte[] signedMessage = decompress(compressedSignedMessage);
        // Separate message and signature
        byte[] signature = slice(signedMessage, 0, SIGNATURE_SIZE);
        byte[] message = slice(signedMessage, SIGNATURE_SIZE, signedMessage.length);
        // Check signature before returning
        if(!verifySignature(message, signature, senderPublicKey)){
            throw new SignatureException("Invalid message signature");
        }
        // Logging
        logDecode(logger, message, signature, compressedSignedMessage, sessionData, encryptedMessage, encryptedSessionData, encodedMessage);
        return message;
    }
}