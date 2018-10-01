import ecse489.helper.Options;
import ecse489.helper.Parser;

public class DnsClient {
    public static void main(String[] args) {
        Parser parser = new Parser(args);
        Options options = parser.buildOptions();
        System.out.println(options.toString());
    }
}
