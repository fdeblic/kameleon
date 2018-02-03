//package kameleon;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.util.Scanner;

public class Kameleon {
	/** The max size the buffer can be */
	public final static int MAX_BUF = 1000000;
	
	/**
	 * Main method
	 * @param args array contening the arguments :
	 * - Path of the file to be encrypted or decrypted (-f)
	 * - The hexadecimal key to encrypt/decrypt the data (-k)
	 */
	public static void main(String[] args) {
		//
		// Variables
		//

		String key = "";
		File argFile = null;
		File saveFile = null;
		
		FileInputStream fileIn = null;
		FileOutputStream fileOut = null;
		
		byte[] buff = null;
		boolean error = false;
		
		//
		// Program
		//
		
		// If no arguments found
		if (args.length == 0) {
			System.out.println("The Kameleon program needs two arguments : the file (-f) and the encoding key (-k)");
			System.exit(-1);
		}
		
		// Searches for the key and file in the arguments
		for (int i = 0 ; i < args.length ; i++) {
			switch (args[i]) {
				// The key
				case "-k":
				case "--key":
					// If next arg exists, it's the key
					if (i+1 < args.length) {
						key = args[i+1].toUpperCase();
						// Skip the next argument
						i++;
					}
				break;
				
				// The file
				case "-f":
				case "--file":
					// If next arg exists, it's the file path
					if (i+1 < args.length) {
						argFile = new File(args[i+1]);
						// Skips the next argument
						i++;
					}
				break;
				
				// Unknown argument
				default:
					System.out.println("Error - unknown parameter: " + args[i]);
					error = true;
				break;
			}
		}
		
		// Verifies the key parameter
		if (key.equals("")) {
			System.out.println("The encoding key is void");
			error = true;
		} else if (key.length()*8 > 256) {
			System.out.println("The encoding key exceeds 256 bits");
			error = true;
		} else if (!isValidKey(key)) {
			System.out.println("The encoding key must be hexadecimal");
			error = true;
		} else if (reformatKey(key).equals("00")) {
			System.out.println("The encoding key is null");
			error = true;
		}
		
		// Vérifies the file parameter
		if (argFile == null) {
			System.out.println("No file parameter found");
			error = true;
		} else if (!argFile.exists()) {
			System.out.println("File not found : " + argFile.getPath());
			error = true;
		} else if (!argFile.canRead()) {
			System.out.println("The file can't be read");
			error = true;
		} else if (argFile.length() == 0) {
			System.out.println("The file is empty");
			error = true;
		} else if (argFile.length() > 20e6) {
			System.out.println("The file exceeds 20MB");
			error = true;
		}
		
		// Stops the program if errors were found
		if (error) {
			System.exit(-1);
		}
		
		// Reformats the key : removes the redondent zeros, ...
		key = reformatKey(key);
		
		// Displays the encryption key reformated
		if (!isEncryptedFile(argFile.getName())) {
			System.out.println("Encryption key : " + key);
		}

		// Opens the export file
		saveFile = new File(addOrRemoveKamExtension(argFile.getPath()));
		if (saveFile.exists()) {
			System.out.println("The output file '"+saveFile.getName()+"' already exists.\nOverwrite it ? (Y/n)");
			Scanner sc = new Scanner(System.in);
			String ans;
			do {
				ans = sc.next().toLowerCase();
			} while (!ans.equals("y") && !ans.equals("n"));
			sc.close();

			if (ans.equals("n")) {
				System.out.println("Exiting the program");
				System.exit(0);
			}
		}
		
		// Opens the different file streams
		try {
			fileIn = new FileInputStream(argFile);
			fileOut = new FileOutputStream(new File(addOrRemoveKamExtension(argFile.getPath())));
		} catch (Exception e) {
			System.out.println("Error - issue while opening the file");
			System.exit(-1);
		}
		
		// Encrypts / decrypts the data
		try {
			// Avoids a too large buffer (max 10^6 bytes)
			if (fileIn.available() < MAX_BUF) {
				buff = new byte[fileIn.available()];
			} else {
				buff = new byte[MAX_BUF];
			}
			
			// Variables for the progress bar
			int total = fileIn.available();
			int done = 0;
			
			while (fileIn.available() != 0) {
				// Avoids to read further than the file size into the buffer
				if (fileIn.available()<buff.length) {
					buff = new byte[fileIn.available()];
				}
				
				// Gets the data
				fileIn.read(buff);
				// Encrypt/decrypt the data into the file
				byte[] d = applyXorKey(buff, key);
				fileOut.write(d);
				// Progress bar
				done += d.length;
				progressPercentage(done, total);
			}
		
			fileIn.close();
			fileOut.close();

			// Ending confirmation message
			if (isEncryptedFile(argFile.getName())) {
				System.out.println("Data has been decrypted to " + addOrRemoveKamExtension(argFile.getName()));
			} else {
				System.out.println("Data has been encrypted to " + addOrRemoveKamExtension(argFile.getName()));
			}
			
		} catch (Exception e) {
			System.out.println("\nError while encoding/decoding the file");
			System.exit(-1);
		}
	}
	
	/**
	 * Method to know if a file is to be encrypted or decrypted thanks to its .kam extension
	 * @param filePath the path of the file
	 * @return true if the file is encrypted, false otherwise
	 */
	private static boolean isEncryptedFile(String filePath) {
		int index = filePath.toLowerCase().indexOf(".kam");
		return (index != -1 && index+4 == filePath.length());
	}
	
	/**
	 * Returns if a key is valid (composed of hexadecimal, can be zero)
	 * @param key the key to validate (without "0x")
	 * @return true if the key is valid, false otherwise
	 */
	private static boolean isValidKey(String key) {
		return key.matches("\\p{XDigit}+");
	}
	
	/**
	 * Reformats a key to get the good number of bytes ("0005a6e" becomes "5a6e")
	 * @param key the key to reformat
	 * @return the key reformatted, "FF" if the key is not valid
	 */
	private static String reformatKey(String key) {
		// Makes sure there's an even number of hexadecimal digits
		if (key.length() % 2 == 1) {
			key = "0" + key;
		}
		
		// If the key is not valid, return a 0xFF key (no modification with XOR)
		if (!isValidKey(key)) {
			return "00";
		}
		
		if (new BigInteger(key, 16).equals(0)) {
			return "00";
		}
		
		// Removes the "00" before the actual key
		int i = 0;
		while (key.charAt(i) == '0' && key.charAt(i+1) == '0') {
			i += 2;
		}
		
		return key.substring(i, key.length());
	}
	
	/**
	 * Encrypts/decrypts the data thanks to the given key
	 * @param content content to encrypt/decrypt
	 * @param hexaKey the key to use for encryption
	 * @return the content modified
	 */
	private static byte[] applyXorKey(byte[] data, String hexaKey) {
		// Vérifies the key's validity
		if (isValidKey(hexaKey)) {
			int[] key = new int[hexaKey.length()];
			for (int i = 0 ; i<key.length; i++) {
				key[i] = Byte.decode("0x"+hexaKey.substring(i, i+1));
			}
			
			// Encrypts the data char by char
			for (int i = 0 ; i < data.length ; i++) {
				data[i] = (byte) (data[i] ^ key[i % key.length]);
			}
		}
		return data;
	}
	
	/**
	 * Automatically adds or remove the .kam extension to a file path
	 * @param path the path to act on
	 * @return the path with(out) the .kam extension
	 */
	private static String addOrRemoveKamExtension(String path) {
		if (isEncryptedFile(path)) {
			return path.substring(0, path.length()-4);
		} else {
			return path + ".kam";
		}
	}
	
	public static void progressPercentage(int done, int total) {
	    if (done > total) {
	        done = total;
	    }
	    
	    int donePercent = 20 * done / total;
	    
	    StringBuilder bar = new StringBuilder("\r[--------------------] " + (100*done/total) + "%");
	    for (int i = 0 ; i < donePercent ; i++) {
	    	bar.setCharAt(i+2, '*');
	    }

	    //String bareRemain = bar.substring(donePercent, bar.length());
	    System.out.print("\r" + bar);
	    if (done == total) {
	        System.out.print("\n");
	    }
	}
}
