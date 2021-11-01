import java.security.SecureRandom;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        // Считывем ключ из файла.
        String userKey = Reader.readText("src/key");
        System.out.println("Key is: " + userKey);

        // Считываем текст для кодирования.
        String textFromFile = Reader.readText("src/test");
        System.out.println("Original text: " + textFromFile);
        // Дополняем строчку до кратности 16.
        int remainder = textFromFile.length() % 16;
        if (remainder != 0) {
            for (int i = 0; i < 16 - remainder; i++) {
                textFromFile = textFromFile.concat(" ");
            }
        }
        // Превращаем текст и ключ в массив байт.
        byte[] textToEncode = RC6.stringToByteArray(textFromFile);
        byte[] key = RC6.stringToByteArray(userKey);

        System.out.println("Starting to encrypt.");
        // Инициализируем массив для хранения зашифрованного текста.
        byte[] cipherText = new byte[textToEncode.length];
        // Отделяем первый кусок текста - 16 байт.
        byte[] slice = Arrays.copyOfRange(textToEncode, 0,  16);
        // Инициализируем вектор инициализации.
        byte[] iv = (new SecureRandom()).generateSeed(16);
        // Шифруем вектор инициализации.
        byte[] encrypted = RC6.encrypt(iv, key);
        // Проводим операцию исключающего или для зашифрованного вектора и первого куска текста.
        byte[] cipherSlice = xor(encrypted, slice);
        // Зашифрованный кусок текста добавляем к массиву для получения конечного результата шифрования.
        System.arraycopy(cipherSlice, 0, cipherText, 0, 16);
        // Делаем те же операции для остатка текста.
        for (int i = 16; i < textToEncode.length; i += 16) {
            // Выделяем следующий кусок текста.
            slice = Arrays.copyOfRange(textToEncode, i, i + 16);
            // Повторно шифруем зашифрованный кусок текста.
            encrypted = RC6.encrypt(cipherSlice, key);
            // Проводим операцию исключающего или для повторно зашифрованного куска и для незашифрованного куска текста.
            cipherSlice = xor(encrypted, slice);
            // Добавляем новый кусок текста к конечному массиву.
            System.arraycopy(cipherSlice, 0, cipherText, i, 16);
        }
        // Конвертируем массив байт в строку.
        String encryptedText = RC6.convertToString(cipherText);
        System.out.println("Encrypted: " + encryptedText);


        System.out.println("Starting to decrypt.");
        // Инициализируем массив байт для конечного дешифрованного текста.
        byte[] decipherText = new byte[textToEncode.length];
        // Выделяем первый кусок.
        slice = Arrays.copyOfRange(cipherText, 0, 16);
        // Шифруем вектор инициализации.
        byte[] decrypted = RC6.encrypt(iv, key);
        // Проводим операцию исключающего или для вектора и куска зашифрованного текста.
        byte[] decipherSlice = xor(decrypted, slice);
        // Копируем полученный кусок в конечный массив.
        System.arraycopy(decipherSlice, 0, decipherText, 0, 16);
        for (int i = 16; i < textToEncode.length; i += 16) {
            // Сохраняем предыдущий зашифрованный кусок в новую переменную.
            byte[] prevSlice = slice;
            // Получаем следующий кусок текста.
            slice = Arrays.copyOfRange(cipherText, i, i + 16);
            // Повторно шифруем зашифрованный кусок текста.
            decrypted = RC6.encrypt(prevSlice, key);
            // Выполняем операцию исключающего или для повторно зашифрованного куска и единожды зашифрованного куска текста.
            decipherSlice = xor(decrypted, slice);
            // Копируем в конечный массив.
            System.arraycopy(decipherSlice, 0, decipherText, i, 16);
        }
        // Конвертируем массив байт в строку.
        String decryptedText = RC6.convertToString(decipherText);
        System.out.println("Decrypted: " + decryptedText);
    }


    private static byte[] xor(byte[] array_1, byte[] array_2) {
        byte[] result = new byte[array_1.length];

        int i = 0;
        for (byte b : array_1) {
            result[i] = (byte) (b ^ array_2[i++]);
        }
        return result;
    }
}
