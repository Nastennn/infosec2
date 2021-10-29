import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class RC6 {


    // Константы для операций сдвига
    private static int r = 20, w = 32;
    // Крипто-ключ
    private static int[] S = new int[r * 2 + 4];

    //
    private static int Pw = 0xB7E15163;
    private static int Qw = 0x9E3779b9;

    // Функция сдвига влево
    private static int rotateL(int n, int x){
        return ((n << x) | (n >>> (w - x)));
    }

    // Функция сдвига вправо
    private static int rotateR(int n, int x){
        return ((n >>> x) | (n << (w - x)));
    }


    public static byte[] hexStringToByteArray(String s) {
        int string_len = s.length();
        byte[] data = new byte[string_len / 2];
        for (int i = 0; i < string_len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
                    .digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Генерация ключа
    public static void keyGen(byte[] key){
        int bytes = w / 8;
        int c = key.length / bytes;
        int[] L = new int[c];
        int index = 0;

        for(int i = 0; i < c; i++){
            L[i] = ((key[index++]) & 0xff | (key[index++] & 0xff) << 8 | (key[index++] & 0xff) << 16 | (key[index++] & 0xff) << 24);
        }
        S[0] = Pw;

        for(int i = 1; i <= 2*r+3; i++){
            S[i] = S[i-1] + Qw;
        }

        int A = 0, B = 0, i = 0,j =0;
        int v = 3 * Math.max(c, 2*r+4);

        for(int k = 1;k <= v; k++){
            A = S[i] = rotateL(S[i] + A + B, 3);
            B = L[j] = rotateL(L[j] + A + B, A+B);
            i = (i + 1) % (2 * r + 4);
            j = (j + 1) % c;
        };
    }

    public static String convertToHex(byte[] text){
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length; i++) {
            out.append(String.format("%02x ", text[i]));
        }
        return out.toString();
    }

    public static byte[] allignHex(int regA,int regB, int regC, int regD){
        int[] data = new int[4];
        byte[] text = new byte[w / 2];

        data[0] = regA;
        data[1] = regB;
        data[2] = regC;
        data[3] = regD;

        for(int i = 0;i < text.length;i++){
            text[i] = (byte)((data[i/4] >>> (i%4)*8) & 0xff);
        }
        return text;
    }

    public static byte[] encrypt(byte[] plainText, byte[] userKey){
        int regA, regB, regC, regD;
        int index = 0, temp1, temp2, swap;

        regA = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8| (plainText[index++] & 0xff) << 16| (plainText[index++] & 0xff)<<24);
        regB = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8| (plainText[index++] & 0xff) << 16| (plainText[index++] & 0xff)<<24);
        regC = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8| (plainText[index++] & 0xff) << 16| (plainText[index++] & 0xff)<<24);
        regD = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8| (plainText[index++] & 0xff) << 16| (plainText[index++] & 0xff)<<24);

        keyGen(userKey);

        regB = regB + S[0];
        regD = regD + S[1];

        for(int i = 1; i <= r ; i++){
            temp1 = rotateL(regB * (regB * 2 + 1), (int)(Math.log(w)/Math.log(2)));
            temp2 = rotateL(regD * (regD * 2 + 1), (int)(Math.log(w)/Math.log(2)));
            regA = (rotateL(regA ^ temp1, temp2)) + S[i * 2];
            regC = (rotateL(regC ^ temp2, temp1)) + S[i * 2 + 1];

            swap = regA;
            regA = regB;
            regB = regC;
            regC = regD;
            regD = swap;
        }

        regA = regA + S[r * 2 + 2];
        regC = regC + S[r * 2 + 3];

        return allignHex(regA, regB, regC, regD);
    }

    public static byte[] decrypt(byte[] cipherText, byte[]userKey){
        int regA, regB, regC, regD;
        int index = 0, temp1, temp2, swap;

        regA = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8| (cipherText[index++] & 0xff) << 16| (cipherText[index++] & 0xff)<<24);
        regB = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8| (cipherText[index++] & 0xff) << 16| (cipherText[index++] & 0xff)<<24);
        regC = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8| (cipherText[index++] & 0xff) << 16| (cipherText[index++] & 0xff)<<24);
        regD = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8| (cipherText[index++] & 0xff) << 16| (cipherText[index++] & 0xff)<<24);

        keyGen(userKey);

        regC = regC - S[r * 2 + 3];
        regA = regA - S[r * 2 + 2];

        for(int i = r; i >= 1 ; i--){
            swap = regD;
            regD = regC;
            regC = regB;
            regB = regA;
            regA = swap;

            temp2 = rotateL(regD * (regD * 2 + 1), (int)(Math.log(w)/Math.log(2)));
            temp1 = rotateL(regB * (regB * 2 + 1), (int)(Math.log(w)/Math.log(2)));
            regC =  rotateR(regC - S[i * 2 + 1], temp1) ^ temp2;
            regA =  rotateR(regA -  + S[i * 2], temp2) ^ temp1;
        }

        regD = regD - S[1];
        regB = regB - S[0];

        return allignHex(regA, regB, regC, regD);
    }

}
