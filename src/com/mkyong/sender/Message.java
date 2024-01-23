package com.mkyong.sender;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.swing.JOptionPane;

public class Message {
    private List<String> base64EncodedList;

    public Message(String data, String publicKeyFile, String privateKeyFile) throws InvalidKeyException, Exception {
        base64EncodedList = new ArrayList<>();
        base64EncodedList.add(encodeToBase64(data.getBytes()));
        base64EncodedList.add(encodeToBase64(sign(data, privateKeyFile)));
    }

    public byte[] sign(String data, String keyFile) throws InvalidKeyException, Exception {
        Signature dsa = Signature.getInstance("SHA1withRSA");
        dsa.initSign(getPrivate(keyFile));
        dsa.update(data.getBytes());
        return dsa.sign();
    }

    public PrivateKey getPrivate(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        System.out.println("Private Key Content (Hex): " + bytesToHex(keyBytes));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // Method to convert bytes to hexadecimal representation
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexStringBuilder = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            hexStringBuilder.append(String.format("%02x", b));
        }
        return hexStringBuilder.toString();
    }

    private String encodeToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private void writeToFile(String filename, String extension) throws FileNotFoundException, IOException {
        File f = new File(filename + extension);
        f.getParentFile().mkdirs();

        try (FileOutputStream fos = new FileOutputStream(f)) {
            // Write the Base64-encoded message
            fos.write((base64EncodedList.get(0) + "\n\n").getBytes());

            // Write the Base64-encoded signature
            fos.write((base64EncodedList.get(1) + "\n\n").getBytes());
        }

        System.out.println("Your file " + filename + extension + " is ready.");
    }

    public static void main(String[] args) throws InvalidKeyException, IOException, Exception {
        String data = JOptionPane.showInputDialog("Type your message here");
        Message message = new Message(data, "MyKeys/publicKeyBytes.bin", "MyKeys/privateKeyBytes.bin");
        message.writeToFile("MyData/SignedData", ".txt");
        message.writeToFile("MyData/SignedData", ".bin");
    }
}
