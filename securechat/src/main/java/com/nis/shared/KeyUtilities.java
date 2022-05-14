package com.nis.shared;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;



public class KeyUtilities {
//For asymmetric encryption, we encourage you to use the RSA algorithm in ECB mode with PKCS1 padding. The algorithm specification string in Java is “RSA/ECB/PKCS1Padding”.

    //Generates 1024-bit RSA key pair
    public static KeyPair generateRSAKeys() throws NoSuchAlgorithmException {
        final KeyPairGenerator RSAGenerator = KeyPairGenerator.getInstance("RSA");
        RSAGenerator.initialize(1024);
        return RSAGenerator.generateKeyPair();
    }

}
