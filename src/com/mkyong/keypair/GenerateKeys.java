package com.mkyong.keypair;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class GenerateKeys {

    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public GenerateKeys(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.keyGen = KeyPairGenerator.getInstance("RSA");
        this.keyGen.initialize(keylength);
    }

    public void createKeys() {
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public String getBase64EncodedPrivateKey() {
        return Base64.getEncoder().encodeToString(this.privateKey.getEncoded());
    }

    public String getBase64EncodedPublicKey() {
        return Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
    }

    public void writeToFile(String path, String data) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(data.getBytes());
        }
    }

    public void writeToFile(String path, byte[] data) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(data);
        }
    }


    public void writeKeysToFiles() throws IOException {
        // Write human-readable keys to files
        writeToFile("MyKeys/publicKey.txt", getBase64EncodedPublicKey());
        writeToFile("MyKeys/privateKey.txt", getBase64EncodedPrivateKey());

        // Write byte-encoded keys to files
        writeToFile("MyKeys/publicKeyBytes.bin", this.publicKey.getEncoded());
        writeToFile("MyKeys/privateKeyBytes.bin", this.privateKey.getEncoded());
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        GenerateKeys myKeys = new GenerateKeys(1024);
        myKeys.createKeys();
        myKeys.writeKeysToFiles();

        System.out.println("Keys generated and saved successfully.");
    }
}
