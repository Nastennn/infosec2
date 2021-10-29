import java.io.File;
import java.io.IOException;
import java.util.Scanner;

public class Reader {
    // Читаем файл и строим строку с его содержимым.
    public static String readText(String filePath) {
        StringBuilder res = new StringBuilder();
        try (Scanner scanner = new Scanner(new File(filePath))) {
            while (scanner.hasNextLine()){
                res.append(scanner.nextLine());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return res.toString();
    }
}
