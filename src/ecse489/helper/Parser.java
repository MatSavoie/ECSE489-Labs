package ecse489.helper;

import ecse489.helper.DNS.DNSCategory;
import java.util.Arrays;

public class Parser {
    private static final int MAX_NUM_OF_ARGS = 9;
    private static final int MIN_NUM_OF_ARGS = 2;

    private String[] commands;

    /**
     * Public constructor.
     * @param commands Command line input
     */
    public Parser(String[] commands) {
        this.commands = commands;
    }

    /**
     * Builds and returns an Options object.
     * @return An Options object if no error occurred. Null otherwise.
     */
    public Options buildOptions() {
        Options options = null;
        try {
            checkCommandsLength();
            int retries = scrapeRetries();
            int timeout = scrapeTimeout();
            int port = scrapePort();
            DNSCategory dns = scrapeDNS();
            String[] arr = scrapeServerAndName();
            options = new Options(timeout, retries, port, dns, arr[0], arr[1]);
        } catch(IllegalArgumentException e) {
            System.out.println("ERROR	Incorrect input syntax: " + e.getLocalizedMessage());
        } catch(IllegalArgumentFormatException e) {
            System.out.println("ERROR	Incorrect input syntax: " + e.getLocalizedMessage());
        }
        return options;
    }

    /**
     * Verifies that the number of arguments is valid.
     * @throws IllegalArgumentException
     */
    private void checkCommandsLength() throws IllegalArgumentException {
        if (this.commands.length > MAX_NUM_OF_ARGS) {
            throw new IllegalArgumentException("Expected at most " + MAX_NUM_OF_ARGS + " arguments, but got " +
                    this.commands.length + " arguments instead.");
        } else if (this.commands.length < MIN_NUM_OF_ARGS) {
            throw new IllegalArgumentException("Expect at least " + MIN_NUM_OF_ARGS + " arguments, but got " +
                    this.commands.length + " argument instead.");
        }
    }

    /**
     * Scrapes the command line arguments for the number of retries to perform.
     * @return An integer representing the number of retries. Default = 3
     * @throws IllegalArgumentFormatException
     */
    private int scrapeRetries() throws IllegalArgumentFormatException {
        int index = Arrays.asList(this.commands).indexOf("-r");
        int retries = 3;
        // Found -r argument
        if (index != -1) {
            try {
                retries = Integer.parseInt(this.commands[index + 1]);
            } catch (Exception e) {
                throw new IllegalArgumentFormatException("Excepted integer after -r.");
            }
        }
        return retries;
    }

    /**
     * Scrapes the command line arguments for the timeout.
     * @return An integer representing the timeout in seconds. Default = 5
     * @throws IllegalArgumentFormatException
     */
    private int scrapeTimeout() throws IllegalArgumentFormatException {
        int index = Arrays.asList(this.commands).indexOf("-t");
        int timeout = 5;
        // Found -r argument
        if (index != -1) {
            try {
                timeout = Integer.parseInt(this.commands[index + 1]);
            } catch (Exception e) {
                throw new IllegalArgumentFormatException("Excepted integer after -t.");
            }
        }
        return timeout;
    }

    /**
     * Scrapes the command line arguments for the port number.
     * @return An integer representing the port number. Default = 53
     * @throws IllegalArgumentFormatException
     */
    private int scrapePort() throws IllegalArgumentFormatException {
        int index = Arrays.asList(this.commands).indexOf("-p");
        int port = 53;
        // Found -r argument
        if (index != -1) {
            try {
                port = Integer.parseInt(this.commands[index + 1]);
            } catch (Exception e) {
                throw new IllegalArgumentFormatException("Excepted integer after -t.");
            }
        }
        return port;
    }

    /**
     * Scrapes the command line arguments for the type of DNS request.
     * @return An DNS enum
     */
    private DNSCategory scrapeDNS() {
        if (Arrays.asList(this.commands).indexOf("-mx") != -1) {
            return DNSCategory.MX;
        }
        if (Arrays.asList(this.commands).indexOf("-ns") != -1) {
            return DNSCategory.NS;
        }
        return DNSCategory.A;
    }

    /**
     * Scrapes the command line arguments for an IPv4 address indicating the authoritative DNS server
     * and a domain name to obtain DNS records on.
     * @return An array of String arr[0] -> Server IP, arr[1] -> Domain name
     * @throws IllegalArgumentFormatException
     */
    private String[] scrapeServerAndName() throws IllegalArgumentFormatException {
        String[] arr;
        int index = -1;
        for (int i = 0; i < this.commands.length; i++) {
            if (this.commands[i].contains("@")) {
                index = i;
                break;
            }
        }
        try {
            String server = this.commands[index].substring(1);
            String name = this.commands[index + 1];
            arr = new String[2];
            arr[0] = server;
            arr[1] = name;
        } catch (Exception e) {
            throw new IllegalArgumentFormatException("Expected DNS server IP address and domain name.");
        }
        return arr;
    }
}



