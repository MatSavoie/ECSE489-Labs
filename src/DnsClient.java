import java.io.IOException;

import ecse489.helper.Options;
import ecse489.helper.Parser;
import ecse489.helper.DNS.Request;

public class DnsClient {
    public static void main(String[] args) {
        Parser parser = new Parser(args);
        Options options = parser.buildOptions();
        if (options != null) {
        	try {
            	Request areq = new Request(options);

            	// Obtain response from the request
	            areq.getResponse();
            } catch(IOException e) {
            	System.out.println("ERROR	Socket Input/Output error");
            	System.out.println("Stack trace printed below");
            	e.printStackTrace();
            }
        }
    }
}
