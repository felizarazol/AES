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
import java.util.Arrays;

/**
 *  Represents a key for an AES implementation
 *
 */
public class Key extends Functions {
	private byte[] key;
	private int keyCount;
	private int keyCountTotal;
	private int Nb, Nr, Nk;
	
	/**
	 *  Construct the key
	 * 
	 *  @param key  bytes representing the key
	 *  @param Nb   Number of columns (32-bit words) comprising the State. For this standard, Nb = 4
	 *  @param Nr   Number of rounds
	 *  @param Nk   Number of 32 bit words comprising the cipher key
	 */
	public Key(byte[] key, int Nb, int Nr, int Nk) {
		this.key  = new byte[4 * Nk * (Nr + 1)];
		this.keyCount = 0;
		this.keyCountTotal = (Nr+1)*16;
                //System.out.println(keyCountTotal+" kkttt");
		this.Nb = Nb;
		this.Nr = Nr;
		this.Nk = Nk;
		keyExpansion(key);
	}
	
	
	/**
	 * 
	 *  @param key  bytes representing the initial key
	 */
	private void keyExpansion(byte[] key) {
		byte[] temp = new byte[4];
		
		int i = 0;
		
		while (i < 4*Nk) {
			this.key[i] = key[i];
			i++;
		}
		
		System.out.println("Initial key: " + Functions.bytesToHex(this.key));
		
		i = Nk;
		
		while (i < Nb * (Nr + 1)) {
			for (int tmp = 0; tmp < 4; tmp++) {
				temp[tmp] = this.key[((i-1) * 4) + tmp];
			}
			
			if (i % Nk == 0) {
				temp = subWord(rotWord(temp,1));
				temp = xorWords(temp, rCon(i/Nk));
			}
			else if (Nk > 6 && (i % Nk) == 4) {
				temp = subWord(temp);
			}
			for (int k = 4*i; k < (4*i) + 4; k++) {
				this.key[k] = (byte)(this.key[k - (4*Nk)] ^ temp[k % (4*i)]);				// k % 4*i produces 0, 1, 2, 3
			}
			i++;
		}
	}
	
	
	/**
	 *  Takes int representing the power of x + 1
	 *  
	 * @param pow  power of x + 1
	 * @return     word representing {xPow}{00}{00}{00}
	 * 
	 */
	private byte[] rCon(int pow) {
		byte[] roundConstant = new byte[4];
		byte xPow = 0x01;
		for (int i = 0; i < (pow - 1); i++) {
			xPow = xtime(xPow);
		}
		roundConstant[0] = xPow;
		roundConstant[1] = 0x00;
		roundConstant[2] = 0x00;
		roundConstant[3] = 0x00;
		
		return roundConstant;
	}
	
	
	/**
	 *  Takes in 2 words and xor's them
	 *  
	 *  @param word1  first word
	 *  @param word2  second word
	 *  @return       new word with new[i] = word1[i] xor word2[i]
	 */
	private byte[] xorWords(byte[] word1, byte[] word2) {
		byte[] result = new byte[4];

		for (int i = 0; i < 4; i++) {
			result[i] = (byte)(word1[i] ^ word2[i]);
		}
		
		return result;
	}
	
	
	/**
	 *  returns the next 16 bytes of the expanded key
	 *  
	 *  @return  next 16 bites of the expanded key
	 */
	public byte[] getKey() {
		byte[] keyPart = Arrays.copyOfRange(this.key, keyCount, keyCount + 16);
		keyCount += 16;
		return keyPart;
	}
	
	
	/**
	 *  returns the previous 16 bytes of the expanded key
	 *  
	 *  @return  previous 16 bites of the expanded key
	 */
	public byte[] getDecryptKey() {
		byte[] keyPart = Arrays.copyOfRange(this.key, keyCountTotal - 16, keyCountTotal);
		keyCountTotal -= 16;
		return keyPart;
	}
        
        public String prettyPrint(byte[] key) {		
            String prettyString = new String("");
		System.out.println("________________");
                prettyString += "_____________\n";
		for (int i = 0; i < 4; i++) {
			System.out.print("| ");
                        prettyString += "| ";
			for (int k = 0+i ; k < 16; k=k+4) {
                                prettyString += String.format("%02X", key[k]) + " ";
				System.out.print(String.format("%02X", key[k]) + " ");
			}
                        prettyString += " |\n";
			System.out.println(" |");
		}
                prettyString += "|___________|\n";
		System.out.println("|______________|");
                
                return prettyString;
	}
	
	
	/**
	 *  Resets the index counter so the key can be used again to encrypt the next 16-bytes
	 */
	public void resetCounter() {
		keyCount = 0;
	}
	
	
	public void resetDecryptCounter() {
		keyCount = 4 * Nb * (Nr + 1);
	}
}