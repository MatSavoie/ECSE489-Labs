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
		// RD: 1		(Recursion desired)
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
				buffer.add(new Byte((byte) 0x0F));
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

	private String stripeExtraDot(String record) {
		int counter = 0;
		for (int rem = record.length() - 1; rem >= 0; rem--) {
			if (record.charAt(rem) == '.') {
				counter++;
			} else {
				break;
			}
		}

		record = record.substring(0, record.length() - counter);

		counter = 0;
		for (int rem = 0; rem < record.length(); rem++) {
			if (record.charAt(rem) == '.') {
				counter++;
			} else {
				break;
			}
		}
		record = record.substring(counter, record.length());

		return record;
	}

	private String parseInfoRecursive(byte[] response, int pointer) {
		String name = "";
		int length = 0;
		int offset = 0;
		while ((response[pointer + offset] & 0x000000FF) != 0x00) {
			if ((response[pointer + offset] & 0x000000FF) != 0xC0) {
				length = (response[pointer + offset++] & 0x000000FF);
			}
			if ((response[pointer + offset] & 0x000000FF) == 0xC0) {
				return name += parseInfoRecursive(response, response[pointer + offset + 1]);
			}

			for (int i = 0; i < length; i++) {
				if ((response[pointer + offset] & 0x000000FF) != 0xC0) {
					name += (char) response[pointer + offset++];
				} else {
					return name += parseInfoRecursive(response, response[pointer + offset - 1]);
				}
			}
			name += ".";
		}
		return name;
	}

	/**
	 * Parses through a record and returns a String representing that record. Recommended to
	 * stripe extra dots in the record.
	 * @param response - An array of bytes representing a DNS response.
	 * @param pointer - An integer pointer indicating the start of data. 
	 * @param length - An integer representing the data length.
	 * @return A String representing the record.
	 */
	private String parseInfo(byte[] response, int pointer, int length) {
		String name = "";
		int counter = 0;
		for (int offset = 0; offset < length;) {
			// Verify that at this location the data is not pointing at a different location
			if ((response[pointer + offset] & 0x000000FF) == 0xC0){
				name += ".";
				return name += parseInfoRecursive(response, response[pointer + offset + 1]);
			} 

			// Verify that at this location the data is not null
			else if((response[pointer + offset] & 0x000000FF) == 0x00) {
				return name;
			} else {
				counter = (response[pointer + offset++] & 0x000000FF);
				while (counter > 0) {
					if ((response[pointer + offset] & 0x000000FF) != 0xC0 &&
						(response[pointer + offset] & 0x000000FF) != 0x00) {
						counter--;
						name += (char) response[pointer + offset++];
					}
					try {
						if ((response[pointer + offset] & 0x000000FF) == 0x00) {
							return name;
						}
	
						if ((response[pointer + offset] & 0x000000FF) == 0xC0){
							name += ".";
							return name += parseInfoRecursive(response, response[pointer + offset + 1]);
						}
					} catch (IndexOutOfBoundsException e) {
						return name;
					}
				}
				name += ".";
			}
		}

		return name;
	}

	/**
	 * Parses through a IPv4 record and returns a String representing an IPv4 address.
	 * @param response - An array of bytes representing a DNS response.
	 * @param pointer - An integer pointer indicating the start of data.
	 * @return A String representing an IPv4 address.
	 */
	private String parseIPv4(byte[] response, int pointer) {
		String ip = "";
		for(int i = 0 ; i < 4; i++) {
			ip += (response[pointer + i] & 0x000000FF);
			if (i != 3) {
				ip += ".";
			}
		}
		return ip;
	}

	/**
	 * Obtains a response from a DNS server using UDP Sockets.
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
					System.out.println("ERROR	No response received after " + this.timeout + " seconds: retry " 
							+ this.tries + " out of " + this.retries);
					this.tries++;
				}
			}

			// Number of tries exceed the maximum allowed number of retries
			// Exit method
			if (this.tries > this.retries) {
				System.out.println("ERROR	Maximum number of " + this.retries + " retries exceeded");
				return;
			}

			// Obtains response and strips away trailing 0x00 bytes
			byte[] rawIncomingData = incomingPacket.getData();
			byte[] strippedData = stripResponse(rawIncomingData);

			// Parse the response and print out important information
			parseAndPrintResponse(strippedData);		
		} catch (IllegalArgumentFormatException e) {
			System.out.println("Error	Incorrect input syntax: " + e.getLocalizedMessage());
		}
	}

	/**
	 * Parses through the response and prints out records, their TTL, types and whether they come from
	 * an authoritative source or not.
	 * @param response - An array of bytes representing a DNS response.
	 */
	public void parseAndPrintResponse(byte[] response) {
		boolean printRecordsLabel = true;
		boolean printAuthRecordsLabel = true;
		boolean printAddRecordsLabel = true;
		boolean authority = false;
		// Proceed only if the DNS Transaction ID is valid
		if (response[0x00] == ID_0 && response[0x01] == ID_1) {
			// QR verification
			if ((response[0x02] & ((byte) 0x80)) != (byte) 0x80) {
				System.out.println("ERROR	Expected response but received query instead...");
				return;
			}

			// AA verification
			if ((response[0x02] & ((byte) 0x04)) == (byte) 0x04) {
				authority = true;
				System.out.println("Responding server is an authority for the domain name");
			}

			// RA verification
			if ((response[0x03] & ((byte) 0x80)) == (byte) 0x00) {
				System.out.println("WARNING		Recursion desired but not supported...");
			}

			// RCode verification
			if ((response[0x03] & ((byte) 0x0F)) != (byte) 0x00) {
				switch(response[0x03] & (byte) 0x0F) {
					case (byte) 0x01:
						System.out.println("ERROR	Format error"); break;
					case (byte) 0x02:
						System.out.println("ERROR	Server failure"); break;
					case (byte) 0x03:
						System.out.println("ERROR	Name error - domain name does not exist in the query"); break;
					case (byte) 0x04:
						System.out.println("ERROR	Not implemented - "); break;
					case (byte) 0x05:
						System.out.println("ERROR	Refused"); break;
				}
				return;
			}

			// Shift the upper byte by 8 to reconstruct a short with the lower byte
			// ANCOUNT
			int numOfAnswers = ((response[0x06] << 8) & 0x0000FF00) | (response[0x07] & 0x000000FF);
			// NSCOUNT
			int numOfAuthAnswers = ((response[0x08] << 8) & 0x0000FF00) | (response[0x09] & 0x000000FF);
			// ARCOUNT
			int numOfAddAnswers = ((response[0x0A] << 8) & 0x0000FF00) | (response[0x0B] & 0x000000FF);

			// No records were found
			if (numOfAnswers + numOfAuthAnswers + numOfAddAnswers == 0) {
				System.out.println("NOTFOUND");
				return;
			}

			// Search for 0x00 padding which indicates the end of the query name section
			// Start search at offset 0x0C which points to the start query name section
			int i = 0x0C;
			do {
				i++; 
			} while (response[i] != 0x00);


			// Add 5 to pointer to the end of the query name section to obtain the pointer to the start of the response section
			// 0x00 padding <- (pointer at this location currently)
			// 0x0000 Query Type
			// 0x0000 Query Class
			// 0x00... Response section
			int parserPointer = i + 0x05;

			try {
				while(parserPointer < response.length) {
					// Keep track of the record labels to print
					if (numOfAnswers > 0) { 
						if (printRecordsLabel) {
							printRecordsLabel = false;
							System.out.println("\n***Answer Section (" + numOfAnswers + " records)***");
						}
						numOfAnswers--;
					} else if (numOfAuthAnswers > 0) {
						if (printAuthRecordsLabel) {
							printAuthRecordsLabel = false;
							System.out.println("\n***Authority Section (" + numOfAuthAnswers + " records)***");
						}
						numOfAuthAnswers--;
					} else if (numOfAddAnswers > 0) {
						if (printAddRecordsLabel) {
							printAddRecordsLabel = false;
							System.out.println("\n***Additional Section (" + numOfAddAnswers + " records)***");
						}
						numOfAddAnswers--;
					}
					
					// Indicates the start of a new record. 0xC0 points to a name inside of the response
					if (response[parserPointer] == ((byte) 0xC0)) {
						parserPointer += 2;
					}

					// Indicates no results related to name or compression was not used by the server
					// Skip name verification since our DNS request only allows to query 1 host at a time
					else {
						while (response[parserPointer] != 0x00) {
							parserPointer++;
						}
						parserPointer++;
					}

					// Obtains the response type, class, TTL and data length
					int responseType = ((response[parserPointer++] << 8) & 0x0000FF00) | (response[parserPointer++] & 0x000000FF);
					int responseClass = ((response[parserPointer++] << 8) & 0x0000FF00) | (response[parserPointer++] & 0x000000FF);
					int responseTTL = ((response[parserPointer++] << 24) & 0xFF000000) | ((response[parserPointer++] << 16) & 0x00FF0000) |
									  ((response[parserPointer++] << 8) & 0x0000FF00) | (response[parserPointer++] & 0x000000FF);
					int length = ((response[parserPointer++] << 8) & 0x0000FF00) | (response[parserPointer++] & 0x000000FF);
					
					// Print results depending on the response type
					if ((byte) responseType == 0x01) {
						System.out.print("IP	" + parseIPv4(response, parserPointer) + "	" + responseTTL +  "	");
					}
					else if ((byte) responseType == 0x02) {
						String nsRecord = parseInfo(response, parserPointer, length);
						System.out.print("NS	" + stripeExtraDot(nsRecord) + "	" + responseTTL + "	");
					}
					else if ((byte) responseType == 0x05) {
						String cnameRecord = parseInfo(response, parserPointer, length);
						System.out.print("CNAME	" + stripeExtraDot(cnameRecord) + "	" + responseTTL + "	");
					}
					else if ((byte) responseType == 0x06) {
						String soaRecord = parseInfo(response, parserPointer, length);
						System.out.print("SOA	" + stripeExtraDot(soaRecord) + "	" + responseTTL);
						parserPointer += length;
						continue;
					}
					else if ((byte) responseType == 0x0F) {
						int preference = ((response[parserPointer] << 8) & 0x0000FF00) | (response[parserPointer + 1] & 0x000000FF);
						String mxRecord = parseInfo(response, parserPointer + 2, length - 2);
						System.out.print("MX	" + stripeExtraDot(mxRecord) + "	" + preference + "	" + responseTTL + "	");
					}
					else {
						System.out.println("ERROR	Type not supported...");
						parserPointer += length;
						continue;
					}

					// Prints if the request server is authoritative or not
					if (authority) {
						System.out.println("	auth");
					} else {
						System.out.println("	nonauth");
					}
					
					parserPointer += length;
				}
			} catch (IndexOutOfBoundsException e) {
				System.out.println("ERROR	An issue occurred while parsing through the message. It might have been truncated.");
				e.printStackTrace();
			}
		} else {
			// DNS Transaction ID mismatch...
			System.out.println("ERROR	Invalid DNS Transaction ID: received -> " 
					+ Integer.toHexString(((((int) response[0]) << 8) & 0x0000FF00) | (((int) response[1]) & 0x000000FF)) 
					+ " expected -> " 
					+ Integer.toHexString(((((int) ID_0) << 8) & 0x0000FF00) | (((int) ID_1) & 0x000000FF)));
		}
	}
}
