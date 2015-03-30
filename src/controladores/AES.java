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
import com.sun.org.apache.bcel.internal.generic.AALOAD;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import javax.swing.JOptionPane;

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
        public static ArrayList<ArrayList> roundsArray =  new ArrayList<ArrayList>();// este arreglo contiene un ArrayList de matrices por cada round de cifrado
        public static ArrayList<ArrayList> roundsDesArray =  new ArrayList<ArrayList>();// este arreglo contiene un ArrayList de matrices por cada round de descifrado
	
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
				JOptionPane.showMessageDialog(null, "Tamaño de llave invalido", "Error", JOptionPane.ERROR_MESSAGE);
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
            /*
                este arreglo contiene las matrices desde el primer round en el orden:
                Matriz de inicio (ARK)
                SB
                SR
                MC // en el último round no hay MC por lo tanto lo rellenamos de 0s
                RoundKey
            */
            ArrayList<String> matrixArray =  new ArrayList<String>();
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
                        matrixArray.add(state.prettyPrint());
                        matrixArray.add("");//SB round 0
                        matrixArray.add("");//SR round 0
                        matrixArray.add("");//MC round 0
                        byte[] keyByte=key.getKey();
			state.addRoundKey(keyByte);
                        matrixArray.add(key.prettyPrint(keyByte));//RK round 0
                        roundsArray.add(matrixArray);
                        matrixArray = new ArrayList<String>();
			for (int k = 1; k < (Nr); k++) {
                            System.out.println("Nr"+k);
                            matrixArray.add(state.prettyPrint());
                            state.subBytes();
                            matrixArray.add(state.prettyPrint());
                            state.shiftRows();
                            matrixArray.add(state.prettyPrint());
                            state.mixColumns();
                            matrixArray.add(state.prettyPrint());
                            keyByte=key.getKey();
                            matrixArray.add(key.prettyPrint(keyByte));
                            //key.prettyPrint(keyByte);
                            state.addRoundKey(keyByte);
                            roundsArray.add(matrixArray);
                            matrixArray= new ArrayList<String>();
			}       
                        matrixArray.add(state.prettyPrint());
			state.subBytes();											// final round does not include mixColumns()
                        matrixArray.add(state.prettyPrint());
                        state.shiftRows();
                        matrixArray.add(state.prettyPrint());
                        matrixArray.add(""); //MC del último round
                        keyByte=key.getKey();
			state.addRoundKey(keyByte);
                        matrixArray.add(key.prettyPrint(keyByte));
			//state.prettyPrint();
			byte[] stateBytes = state.getBytes();
			for (int n = 0; n < 16; n++) {
				encrypted[i+n] = stateBytes[n];
			}
			if ((i + 16) != encryptedLength) {
				key.resetCounter();
			}
                        roundsArray.add(matrixArray);
                        //System.out.println("MATRIX"+matrixArray);
                        //System.out.println("ROUNDS"+roundsArray);
                        matrixArray = new ArrayList<String>();
		}
		//System.out.println(roundsArray);
		return encrypted;
	}
	
	
	/**
	 *  Takes in a cipher and decrypts it
	 *  
	 *  @param c  cipher to decrypt
	 *  @return   decrypted message
	 */
	public byte[] decrypt(byte[] cipher) {
            /*
                Para descifrar el orden de las matrices es:
                ARK
                MC
                SR
                SB
                RoundKey
                
            */
            ArrayList<String> matrixArray =  new ArrayList<String>();
		int decryptedLength = cipher.length;
		byte[] decrypted = new byte[decryptedLength];
		
		for (int i = 0; i < cipher.length; i += 16) {						// break up the byte array into 16-byte 2d arrays
			this.state = new State(Arrays.copyOfRange(cipher, i, i + 16));
                        matrixArray.add(state.prettyPrint());
                        matrixArray.add("");// MC Round de entrada
                        matrixArray.add("");// MC Round de entrada
                        matrixArray.add("");// MC Round de entrada
                        byte[] keyDecripted = key.getDecryptKey();
                        matrixArray.add(key.prettyPrint(keyDecripted));
                        roundsDesArray.add(matrixArray);
                        matrixArray = new ArrayList<String>();
                        
			state.addRoundKey(keyDecripted);
                        matrixArray.add(state.prettyPrint());
                        matrixArray.add("");//MC primer round
                        state.invShiftRows();
                        matrixArray.add(state.prettyPrint());// SR
                        state.invSubBytes();
                        matrixArray.add(state.prettyPrint());// SB
			keyDecripted = key.getDecryptKey();
                        matrixArray.add(key.prettyPrint(keyDecripted));
                        roundsDesArray.add(matrixArray);
                        matrixArray = new ArrayList<String>();
                        
			for (int k = 0; k < (Nr - 1); k++) {
                                
                            state.addRoundKey(keyDecripted);
                            matrixArray.add(state.prettyPrint());
                            state.invMixColumns();
                            matrixArray.add(state.prettyPrint());
                            state.invShiftRows();
                            matrixArray.add(state.prettyPrint());// SR
                            state.invSubBytes();
                            matrixArray.add(state.prettyPrint());// SB
                            keyDecripted = key.getDecryptKey();
                            matrixArray.add(key.prettyPrint(keyDecripted));
                            roundsDesArray.add(matrixArray);
                            matrixArray = new ArrayList<String>();
			}
                        
			state.addRoundKey(keyDecripted);
			
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
//	public static void main(String[] args) {
////		if (args.length < 1) {
////			System.out.println("Usage: <message> <key>");
////			System.out.println("The message can be any length but the key must be 16, 24, or 32 charactors long.");
////			System.exit(1);
////		}
//		AES aes;
////		if (args.length < 2) {
////			aes = new AES();
////		}
////		else {
//                byte[] testBytes = Functions.hexStringToByteArray("414553206573206d757920666163696c");
//			
//                byte[] testKey = Functions.hexStringToByteArray("2B7e151628aed2a6abf7158809cf4f3c");
//                
//                byte[] ciphertext = Functions.hexStringToByteArray("E448E574A374D90CC33C22AF9B8EAB7F");
//                aes = new AES(testKey);	
////        }
//		//byte[] cipher = aes.encrypt(testBytes);
//		//byte[] cipher = aes.encrypt(Functions.hexStringToByteArray("00112233445566778899aabbccddeeff"));
//		//byte[] cipher = aes.encrypt(new String("<Insert generic super duper secret private message here#!@#$%!@$@!%>").getBytes());
//		//byte[] cipher = aes.encrypt(hexStringToByteArray("00000000000000000000000000000000"));
//		//System.out.println("Cipher:  " + Functions.bytesToHex(cipher));
//		System.out.println("Message: " + new String(aes.decrypt(ciphertext)));
//                System.out.println(aes.Nr);
//	}
}
