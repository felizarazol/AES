/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package controladores;

/**
 *
 * @author Julian
 */
import java.security.SecureRandom;
import java.util.Arrays;

/**
 *  Implementation of AES
 *  
 *  NOTE: if the message is not a multiple of 16-bytes, this will zero extend the end of the message
 *  		to a multiple of 16 bytes. For instance, if the message is 00112233, it will be decrypted
 *  		as 0011223300000000. This is not a problem with printing ASCII as '00' represents the null
 *  		character and signifies the end of a string anyways
 */
public class AES {
	// these are for 128-bit
	private final int Nb = 4; // Number of columns (32 bit words) comprising the state
	private int Nk;	// Number of 32 bit words comprising the cipher key
	private final int Nr;	// Number of rounds
	private SecureRandom rand = new SecureRandom();
	private Key key;
	private State state;
	
	/**
	 *  Takes in a 128, 296, or 256-bit key to use as the symmetric key
	 *  If the key is null, this will generate a 128-bit key to use
	 *  
	 *  @param key
	 */
	public AES(byte[] key) {
		if (key == null) {
			key = new byte[16];
			rand.nextBytes(key);
			this.Nk = 4;
		}
		else {
			int key_len = key.length*2;
			System.out.println("Key Length: " + key_len);
			
			if (key_len == 32 || key_len == 48 || key_len == 64) {
				this.Nk = key_len / 8;
			}
			else {
				System.out.println("Invalid key size");
				System.exit(1);
			}
		}
                Nr = Nk + 6;
		this.key = new Key(key, Nb, Nr, Nk);
	}
	
	/** 
	 *  Key is not provided at the time of instantiation.
	 *  Sets key to null and calls alternative constructor
	 */
	public AES() {
		this(null);
	}
	
	/**
	 *  Takes in a message and encrypts it
	 *  
	 *  @param m  message to encrypt
	 *  @return   encrypted message
	 */
	public byte[] encrypt(byte[] message) {
		int encryptedLength;
		if ((message.length % 16) == 0) {
			encryptedLength = message.length;
		}
		else {
			encryptedLength = message.length + 16 - (message.length % 16);
		}
		byte[] encrypted = new byte[encryptedLength];
		
		
		for (int i = 0; i < message.length; i += 16) {					// break up the byte array into 16-byte 2d arrays
			this.state = new State(Arrays.copyOfRange(message, i, i + 16));
			
			System.out.println("round[" + 0 + "].initial: " + "state: " + Functions.bytesToHex(state.getBytes()));
			state.addRoundKey(key.getKey());
			
			for (int k = 0; k < (Nr - 1); k++) {
				System.out.println("round[" + k + "].start: " + "state: " + Functions.bytesToHex(state.getBytes()));
				state.subBytes();
				System.out.println("round[" + k + "].s_box: " + "state: " + Functions.bytesToHex(state.getBytes()));
				state.shiftRows();
				System.out.println("round[" + k + "].s_row: " + "state: " + Functions.bytesToHex(state.getBytes()));
				state.mixColumns();
				System.out.println("round[" + k + "].m_col: " + "state: " + Functions.bytesToHex(state.getBytes()));
				state.addRoundKey(key.getKey());
                                System.out.println("Nr"+k);
			}       
			System.out.println("round[" + (Nr-1) + "].start: " + "state: " + Functions.bytesToHex(state.getBytes()));
			state.subBytes();											// final round does not include mixColumns()
			System.out.println("round[" + (Nr-1) + "].s_box: " + "state: " + Functions.bytesToHex(state.getBytes()));
                        state.shiftRows();
                        System.out.println("round[" + (Nr-1) + "].s_row: " + "state: " + Functions.bytesToHex(state.getBytes()));
			state.addRoundKey(key.getKey());
			
			byte[] stateBytes = state.getBytes();
			for (int n = 0; n < 16; n++) {
				encrypted[i+n] = stateBytes[n];
			}
			if ((i + 16) != encryptedLength) {
				key.resetCounter();
			}
		}
		
		return encrypted;
	}
	
	
	/**
	 *  Takes in a cipher and decrypts it
	 *  
	 *  @param c  cipher to decrypt
	 *  @return   decrypted message
	 */
	public byte[] decrypt(byte[] cipher) {
		int decryptedLength = cipher.length;
		byte[] decrypted = new byte[decryptedLength];
		
		for (int i = 0; i < cipher.length; i += 16) {						// break up the byte array into 16-byte 2d arrays
			this.state = new State(Arrays.copyOfRange(cipher, i, i + 16));

			state.addRoundKey(key.getDecryptKey());
			
			for (int k = 0; k < (Nr - 1); k++) {
				state.invShiftRows();
				state.invSubBytes();
				state.addRoundKey(key.getDecryptKey());
				state.invMixColumns();
			}
			
			state.invShiftRows();										// final round does not include mixColumns()
			state.invSubBytes();
			state.addRoundKey(key.getDecryptKey());
			
			byte[] stateBytes = state.getBytes();
			for (int n = 0; n < 16; n++) {
				decrypted[i+n] = stateBytes[n];
			}
			if ((i + 16) != decryptedLength) {
				key.resetDecryptCounter();
			}
		}
		
		return decrypted;
	}
	
	/**
	 *  tests an encryption and decryption
	 *  
	 *  NOTE: if you insert "\0" anywhere in the string, java will treat this as the "null" character 
	 *  		and end the string. The encryption / decryption still works fine, it just means that simply
	 *  		instantiating a new String is not sufficient. However, not many messages contain the literal 
	 *  		'\0', so for the sake of simplicity, this "error" does exist. 
	 *  
	 *  @param args  args[0] = message
	 *  			 args[1] = key (optional: if none is provided, a random 16-bit key will be generated and used)
	 */
	public static void main(String[] args) {
//		if (args.length < 1) {
//			System.out.println("Usage: <message> <key>");
//			System.out.println("The message can be any length but the key must be 16, 24, or 32 charactors long.");
//			System.exit(1);
//		}
		AES aes;
//		if (args.length < 2) {
//			aes = new AES();
//		}
//		else {
                byte[] testBytes = Functions.hexStringToByteArray("414553206573206d757920666163696c");
			
                byte[] testKey = Functions.hexStringToByteArray("2B7e151628aed2a6abf7158809cf4f3c");
                
                aes = new AES(testKey);	
//        }
		byte[] cipher = aes.encrypt(testBytes);
		//byte[] cipher = aes.encrypt(Functions.hexStringToByteArray("00112233445566778899aabbccddeeff"));
		//byte[] cipher = aes.encrypt(new String("<Insert generic super duper secret private message here#!@#$%!@$@!%>").getBytes());
		//byte[] cipher = aes.encrypt(hexStringToByteArray("00000000000000000000000000000000"));
		System.out.println("Cipher:  " + Functions.bytesToHex(cipher));
		System.out.println("Message: " + new String(aes.decrypt(cipher)));
                System.out.println(aes.Nr);
	}
}