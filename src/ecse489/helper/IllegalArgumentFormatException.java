package ecse489.helper;

/**
 * An illegal argument formatting Throwable.
 */
public class IllegalArgumentFormatException extends Exception {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
     * Constructor for IllegalArgumentFormatException.
     */
    public IllegalArgumentFormatException() {
        super();
    }

    /**
     * @Overload Constructor for IllegalArgumentFormatException.
     * @param message A String representing the message to display.
     */
    public IllegalArgumentFormatException(String message) {
        super(message);
    }
}