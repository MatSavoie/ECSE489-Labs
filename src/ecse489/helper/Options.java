package ecse489.helper;

import ecse489.helper.Parser.DNS;

public class Options {
    private int timeout;
    private int retries;
    private int port;
    private DNS dns;
    private String name;
    private String server;

    /**
     * Public constructor.
     * @param timeout Timeout in seconds
     * @param retries Number of retries
     * @param port Port
     * @param dns DNS request type
     * @param server Authoritative server IP
     * @param name Domain name to lookup
     */
    public Options(int timeout, int retries, int port, DNS dns, String server, String name) {
        this.timeout = timeout;
        this.retries = retries;
        this.port = port;
        this.dns = dns;
        this.name = name;
        this.server = server;
    }

    public int getTimeout() {
        return timeout;
    }

    public int getRetries() {
        return retries;
    }

    public int getPort() {
        return port;
    }

    public DNS getDNS() {
        return dns;
    }

    public String getServer() {
        return server;
    }

    public String getName() {
        return name;
    }

    /**
     * Converts current Object to a String.
     * @return A String representation of the object.
     */
    public String toString() {
        String output = "[Options] Timeout: " + timeout + " Retries: " + retries + " Port: " + port;
        switch (dns) {
            case A:
                output += " DNS: A";
                break;
            case MX:
                output += " DNS: MX";
                break;
            case NS:
                output += " DNS: NS";
                break;
        }
        output += " Server: " + server + " Name: " + name;
        return output;
    }
}
