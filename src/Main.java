import org.bouncycastle.crypto.engines.RC6Engine;
import java.security.SecureRandom;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.io.*;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        System.out.println("Введите ключ: ");
        Scanner scanner = new Scanner(System.in);
        String userKey = scanner.nextLine();

        String textFromFile = Reader.readText("src/test");
        System.out.println("Original text: " + textFromFile);
        byte[] textToEncode = RC6.hexStringToByteArray(textFromFile);
        byte[] key = RC6.hexStringToByteArray(userKey);

        System.out.println("Starting to encrypt.");
        byte[] cipherText = RC6.encrypt(textToEncode,key);

        String encryptedText = RC6.convertToHex(cipherText);
        System.out.println("Encrypted: " + encryptedText);


        System.out.println("Starting to decrypt.");
        byte[] decipherText = RC6.decrypt(cipherText,key);
        String decryptedText = RC6.convertToHex(decipherText);
        System.out.println("Decrypted: " + decryptedText);


    }
}
