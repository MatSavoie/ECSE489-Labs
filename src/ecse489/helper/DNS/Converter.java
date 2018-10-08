package ecse489.helper.DNS;

import ecse489.helper.IllegalArgumentFormatException;

class Converter {
	/**
	 * Converts IPv4 String to a byte array.
	 * @param IPAddress - A String representing an IPv4 address.
	 * @return A byte array
	 * @throws IllegalArgumentFormatException
	 */
	protected static byte[] convertIPv4StringToByteArray(String IPAddress) throws IllegalArgumentFormatException {
		// Splits IPv4 String into String arrays containing numbers
		String[] ipArr = IPAddress.split("[.]");
		if (ipArr.length != 4) {
			throw new IllegalArgumentFormatException("IP address is not type IPv4");
		}
		
		// Converts to IPv4 bytes
		byte[] byteArr = new byte[4];
		for(int i = 0; i < 4; i++) {
			int number = Integer.parseInt(ipArr[i]);
			if (number > 255 || number < 0) {
				throw new IllegalArgumentFormatException("IP address is not within 0 to 255");
			}
			byteArr[i] = (byte) number;
		}
		return byteArr;
	}

	/**
	 * Converts an array of Byte objects into an array of bytes (primitive).
	 * @param arr An array of Bytes (object).
	 * @return An array of bytes (primitive).
	 */
	protected static byte[] convertByteArrToPrimitiveArr (Byte[] arr) {
		byte[] output = new byte[arr.length];
		for (int i = 0; i < arr.length; i++) {
			output[i] = arr[i];
		}
		return output;
	}
}
