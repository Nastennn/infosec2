import java.nio.charset.StandardCharsets;

public class RC6 {
    // Константы для операций сдвига.
    private static int r = 20, w = 32;
    // Крипто-ключ
    private static int[] S = new int[r * 2 + 4];

    // По формулам генерируются два псевдослучайных числа. Для w = 32 они принимают значения, представленные ниже.
    private static int Pw = 0xB7E15163;
    private static int Qw = 0x9E3779b9;

    // Функция сдвига влево.
    private static int shiftL(int n, int x) {
        return ((n << x) | (n >>> (w - x)));
    }

    // Функция генерации массива байтов из строки.
    public static byte[] stringToByteArray(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // Генерация ключа
    public static void keyGen(byte[] key) {
        // Разбиение ключа на машинные слова.
        int bytes = w / 8;
        int c = key.length / bytes;
        int[] L = new int[c];
        int index = 0;

        for (int i = 0; i < c; i++) {
            L[i] = ((key[index++]) & 0xff | (key[index++] & 0xff) << 8 | (key[index++] & 0xff) << 16 | (key[index++] & 0xff) << 24);
        }

        // Инициализация массива ключей.
        S[0] = Pw;
        for (int i = 1; i <= 2 * r + 3; i++) {
            S[i] = S[i - 1] + Qw;
        }
        // Перемешиваем секретный ключ пользователя.
        int A = 0, B = 0, i = 0, j = 0;
        int v = 3 * Math.max(c, 2 * r + 4);

        for (int k = 1; k <= v; k++) {
            A = S[i] = shiftL(S[i] + A + B, 3);
            B = L[j] = shiftL(L[j] + A + B, A + B);
            i = (i + 1) % (2 * r + 4);
            j = (j + 1) % c;
        }

    }
    // Функция генерации строки из массива байт.
    public static String convertToString(byte[] text) {
        return new String(text, StandardCharsets.UTF_8);
    }

    // Объединяем блоки в массив байтов.
    public static byte[] align(int regA, int regB, int regC, int regD) {
        int[] data = new int[4];

        byte[] text = new byte[w / 2];

        data[0] = regA;
        data[1] = regB;
        data[2] = regC;
        data[3] = regD;

        for (int i = 0; i < text.length; i++) {
            text[i] = (byte) ((data[i / 4] >>> (i % 4) * 8) & 0xff);
        }
        return text;
    }
    // Функция шифрования.
    public static byte[] encrypt(byte[] plainText, byte[] userKey) {
        int regA, regB, regC, regD;
        int[] dataBlock= new int[plainText.length/4];
        int index = 0, temp1, temp2, swap;

        // Формирование блоков.
        for(int i=0;i<dataBlock.length;i++) {
            dataBlock[i] =(plainText[index++] & 0xFF)| ((plainText[index++]& 0xFF)<<8) | ((plainText[index++]& 0xFF)<<16)|((plainText[index++]& 0xFF)<<24);
        }
        regA = dataBlock[0];
        regB = dataBlock[1];
        regC=  dataBlock[2];
        regD = dataBlock[3];
        // Генерация ключа для раунда шифрования.
        keyGen(userKey);
        regB = regB + S[0];
        regD = regD + S[1];

        // Операция сдвига смешивает биты в слове.
        for (int i = 1; i <= r; i++) {
            temp1 = shiftL(regB * (regB * 2 + 1), (int) (Math.log(w) / Math.log(2)));
            temp2 = shiftL(regD * (regD * 2 + 1), (int) (Math.log(w) / Math.log(2)));
            //Используем xor в качестве нелинейного преобразования с хорошими показателями перемешивания битового значения входной величины.
            regA = (shiftL(regA ^ temp1, temp2)) + S[i * 2];
            regC = (shiftL(regC ^ temp2, temp1)) + S[i * 2 + 1];
            // Меняем регистры местами.
            swap = regA;
            regA = regB;
            regB = regC;
            regC = regD;
            regD = swap;
        }

        regA = regA + S[r * 2 + 2];
        regC = regC + S[r * 2 + 3];

        // Объединяем блоки.
        return align(regA, regB, regC, regD);
    }

}
