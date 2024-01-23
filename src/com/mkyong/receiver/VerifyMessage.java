package com.mkyong.receiver;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class VerifyMessage {

    private byte[] data;
    private byte[] signature;

    public VerifyMessage(String filename, String keyFile, String extension) throws Exception {
        readFromFile(filename + extension);

        System.out.println(
                verifySignature(data, signature, keyFile)
                        ? "VERIFIED MESSAGE\n----------------\n" + new String(data)
                        : "Could not verify the signature.");
    }

    private void readFromFile(String filename) throws Exception {
        String fileContent = new String(Files.readAllBytes(Paths.get(filename)));
        String[] parts = fileContent.split("\n\n");

        if (parts.length == 2) {
            data = Base64.getDecoder().decode(parts[0]);
            signature = Base64.getDecoder().decode(parts[1]);
            System.out.println(parts);
        } else {
            throw new IllegalStateException("Invalid file format");
        }
    }

    private boolean verifySignature(byte[] data, byte[] signature, String keyFile) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(getPublic(keyFile));
        sig.update(data);
        return sig.verify(signature);
    }

    public PublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
       // System.out.println("Public Key Content (Hex): " + bytesToHex(keyBytes));  // Add this line for debugging
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static void main(String[] args) throws Exception {
       // new VerifyMessage("MyData/SignedData", "MyKeys/publicKeyBytes.bin", ".txt");
        new VerifyMessage("MyData/SignedData", "MyKeys/publicKeyBytes.bin", ".bin");
    }
}
