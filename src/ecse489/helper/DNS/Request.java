package ecse489.helper.DNS;

import ecse489.helper.IllegalArgumentFormatException;
import ecse489.helper.Options;
import ecse489.helper.DNS.Converter;
import ecse489.helper.DNS.DNSCategory;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;

public class Request {
	private DatagramSocket socket;

	private String server;
	private String name;
	private int port;
	private DNSCategory dns;
	private int retries;
	private int timeout;

	private static final byte ID_0 = (byte) 0xEE;
	private static final byte ID_1 = (byte) 0xCE;

	private int tries = 0;

	public Request(Options options) {
		this.server = options.getServer();
		this.name = options.getName();
		this.port = options.getPort();
		this.dns = options.getDNS();
		this.timeout = options.getTimeout();
		this.retries = options.getRetries();
	}

	/**
	 * Builds the buffer based the type of DNS request
	 * @return An array of bytes.
	 */
	private byte[] buildBuffer() {
		ArrayList<Byte> buffer = new ArrayList<Byte>();
		
		// Unique identifier 0xEECE for our DNS
		buffer.add(new Byte(ID_0));
		buffer.add(new Byte(ID_1));

		// QR: 0		(DNS Request)
		// Opcode: 0000 (Standard query)
		// AA: 0		(Authoritative response - reserved for response)
		// TC: 0		(Truncated response - reserved for response)
		// RD: 0		(Recursion not desired)
		buffer.add(new Byte((byte) 0x01));

		// RA: 0		(Recursion supported - reserved for response)
		// Z: 000		(Reserved for future use)
		// Rcode: 0000	(Response code - reserved for response)
		buffer.add(new Byte((byte) 0x00));

		// QDCOUNT: 0x0001	(One question follows) 
		buffer.add(new Byte((byte) 0x00));
		buffer.add(new Byte((byte) 0x01));

		// ANCOUNT: 0x0000	(No answer follows)
		buffer.add(new Byte((byte) 0x00));
		buffer.add(new Byte((byte) 0x00));

		// NSCOUNT: 0x0000	(No records follows)
		buffer.add(new Byte((byte) 0x00));
		buffer.add(new Byte((byte) 0x00));

		// ARCOUNT: 0x0000 	(No additional records follows)
		buffer.add(new Byte((byte) 0x00));
		buffer.add(new Byte((byte) 0x00));

		// Begin building name to buffer. Split string apart using regex on any appearance of "."
		String[] nameInStringArr = this.name.split("[.]");
		for (int i = 0; i < nameInStringArr.length; i++) {
			// Add size of every string and their representation in bytes
			buffer.add(new Byte((byte) nameInStringArr[i].length()));
			for (int j = 0; j < nameInStringArr[i].length(); j++) {
				buffer.add(new Byte((byte) nameInStringArr[i].charAt(j)));
			}
		}

		// Indicates end of name
		buffer.add(new Byte((byte) 0x00));

		// QTYPE: 0x0001	(A Query)
		// QTYPE: 0x0002	(NS Query)
		// QTYPE: 0x000f	(MX Query)
		buffer.add(new Byte((byte) 0x00));
		switch(dns) {
			case A:
				buffer.add(new Byte((byte) 0x01));
				break;
			case NS:
				buffer.add(new Byte((byte) 0x02));
				break;
			case MX:
				buffer.add(new Byte((byte) 0x0f));
				break;
		}

		// QCLASS: 0x0001	(Internet address)
		buffer.add(new Byte((byte) 0x00));
		buffer.add(new Byte((byte) 0x01));

		return Converter.convertByteArrToPrimitiveArr(buffer.toArray(new Byte[buffer.size()]));
	}

	/**
	 * Removes extra 0x00 at the end of the response.
	 * @param response - An array of bytes.
	 * @return An array of bytes with extra bytes removed.
	 */
	private byte[] stripResponse(byte[] response) {
		int stop = 0;
		for (int i = response.length - 1; i >= 0; i--) {
			if (response[i] != (byte) 0x00) {
				stop = i;
				break;
			}
		}
		return Arrays.copyOfRange(response, 0, stop + 1);
	}

	/**
	 * 
	 * @throws IOException
	 */
	public void getResponse() throws IOException {
		try {
			// Summarize DNS query
			System.out.println("\nDnsClient sending request for " + this.name);
			System.out.println("Server: " + this.server);
			switch(dns) {
				case A: System.out.println("Request type: A\n"); break;
				case MX: System.out.println("Request type: MX\n"); break;
				case NS: System.out.println("Request type: NS\n"); break;
			}
			
			byte[] outgoingBuffer = buildBuffer();
			// Since DNS response have an unknown length, use 1500 which is the maximum UDP packet size as limited
			// by IP protocol
			byte[] incomingBuffer = new byte[1500];

			// Converts IPv4 address String into a byte array of size 4
			byte[] serverInByteArr = Converter.convertIPv4StringToByteArray(this.server);

			// Establish a new anonymous DatagramSocket for Client side (us)
			this.socket = new DatagramSocket();

			// Set timeout in milliseconds
			this.socket.setSoTimeout(this.timeout * 1000);

			// Start a timer
			long startTime = System.currentTimeMillis();

			// Create a new UDP packet and send it to Server:Port
			DatagramPacket outgoingPacket = new DatagramPacket(outgoingBuffer, 
					   								   		   outgoingBuffer.length,
					   								   		   InetAddress.getByAddress(serverInByteArr), 
					   								   		   port);
			this.socket.send(outgoingPacket);

			// Create a new UDP packet to receive it from the server
			// Try to receive from the server
			DatagramPacket incomingPacket = new DatagramPacket(incomingBuffer, incomingBuffer.length);
			while(this.tries <= this.retries) {
				try {
					this.socket.receive(incomingPacket);
					System.out.println("Response received after " + ((System.currentTimeMillis() - startTime) / 1000.0) 
							+ " seconds (" + this.tries + " retries)");
					break;
				} catch (SocketTimeoutException e) {
					// Number of tries exceed the maximum allowed number of retries
					// Exit method
					if (this.tries > this.retries) {
						System.out.println("ERROR	Maximum number of " + this.retries + " retries exceeded");
						return;
					}
					System.out.println("ERROR	No response received after " + this.timeout + " seconds: retry " 
							+ this.tries + " out of " + this.retries);
					this.tries++;
				}
			}

			byte[] rawIncomingData = incomingPacket.getData();
			byte[] strippedData = stripResponse(rawIncomingData);
			parseAndPrintResponse(strippedData);		
		} catch (IllegalArgumentFormatException e) {
			System.out.println("Error	Incorrect input syntax: " + e.getLocalizedMessage());
		}
	}

	public void parseAndPrintResponse(byte[] response) {
		// Proceed only if the DNS Transaction ID is verified
		if (response[0] == ID_0 && response[1] == ID_1) {

		} else {
			System.out.println("ERROR	Invalid DNS Transaction ID: received -> " 
					+ Integer.toHexString(((((int) response[0]) << 8) & 0x0000FF00) | (((int) response[1]) & 0x000000FF)) 
					+ " expected -> " 
					+ Integer.toHexString(((((int) ID_0) << 8) & 0x0000FF00) | (((int) ID_1) & 0x000000FF)));
		}
	}
}
