import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public class AES {
	// Look up tables
	// For shift rows
	public static final int[][] sbox = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
	// For inverse shift rows
	public static final int[][] inverseSbox = {{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};
	// Galois table used for mixColumns
	public static final int[][] galois = {{0x02, 0x03, 0x01, 0x01},
			{0x01, 0x02, 0x03, 0x01},
			{0x01, 0x01, 0x02, 0x03},
			{0x03, 0x01, 0x01, 0x02}};
	// Inverse Galois table used for inverse mixColumns
	public static final int[][] inverseGalois = {{0x0e, 0x0b, 0x0d, 0x09},
			{0x09, 0x0e, 0x0b, 0x0d},
			{0x0d, 0x09, 0x0e, 0x0b},
			{0x0b, 0x0d, 0x09, 0x0e}};
	public static final int[] rcon = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
			0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
			0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
			0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
			0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
			0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
			0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
			0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
			0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
			0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
			0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
			0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
			0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
			0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
			0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
			0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};
	
	public static String key;
	public static String iv = "8899AABBCCDDEEFF";
	
	// String line is converted to a matrix state
	public static void stringToMatrix(String line, int[][] matix) {
		 for (int i = 0; i < 4; i++) {
			 for (int j = 0; j < 4; j++) {
				 matix[j][i] = Integer.parseInt(line.substring((8*i)+(2*j), (8*i)+(2*j+2)), 16);
			 }
		 }
	}
	// Matrix is converted to a string
	public static String matrixToString(int state[][]) {
		String t = "";
		for (int i = 0; i < state.length; i++) {
			for (int j = 0; j < state[0].length; j++) {
				String h = Integer.toHexString(state[j][i]).toUpperCase();
				if (h.length() == 1) {
					t += '0' + h;
				} else {
					t += h;
				}
			}
		}
		return t;
	}
	// The sub-key is combined with state. Each element in the state matrix 
	// is XOR'd with each element in the chunk of the expanded key.
	public static void addRoundKey(int state[][], int keyMatrix[][]) {
		for (int i = 0; i < state.length; i++) {
			for (int j = 0; j < state[0].length; j++) {
				state[j][i] ^= keyMatrix[j][i];
			}
		}
	}
	// Replaces state matrix to s-box matrix from look-up table
	public static void subBytes(int state[][]) {
		for (int i = 0; i < state.length; i++) {
			for (int j = 0; j < state[0].length; j++) {
				int hex = state[j][i];
				state[j][i] = sbox[hex / 16][hex % 16];
			}
		}
	}
	// Left shifts nth row by n-1
	public static void shiftRows(int state[][]) {
		for (int i = 1; i < state.length; i++) {
			state[i] = leftRotate(state[i], i);
		}
	}
	// Mix column operation and maps elements from mix column look-up table
	public static void mixColumns(int state[][]) {
		int[][] tarr = new int[4][4];
		for(int i = 0; i < 4; i++)
		{
			System.arraycopy(state[i], 0, tarr[i], 0, 4);
		}
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] = mcLookup(tarr, galois, i, j);
			}
		}
	}
	// Sub-key created using the key for the round
	public static int[][] subKey(int key[][], int round) {
		int[][] roundKey = new int[4][4];
		for (int i = 0; i < roundKey.length; i++) {
			for (int j = 0; j < roundKey.length; j++) {
				roundKey[i][j] = key[i][4 * round + j];
			}
		}
		return roundKey;
	}
	
	public static void copyToNextIv(int next[][], int current[][]) {
		for(int i=0; i<next.length; i++) {
			System.arraycopy(current[i], 0, next[i], 0, next[0].length);
		}
	}
	// Reverse operation of shift rows
	public static void inverseShiftRows(int state[][]) {
		for (int i = 1; i < state.length; i++) {
			state[i] = rightRotate(state[i], i);
		}
	}
	// Reverse operation of subBytes
	public static void inverseSubBytes(int state[][]) {
		for (int i = 0; i < state.length; i++) //Inverse Sub-Byte subroutine
		{
			for (int j = 0; j < state[0].length; j++) {
				int hex = state[j][i];
				state[j][i] = inverseSbox[hex / 16][hex % 16];
			}
		}
	}
	// Reverse operation of mix columns
	public static void inverseMixColumns(int state[][]) {
		int[][] tarr = new int[4][4];
		for(int i = 0; i < 4; i++)
		{
			System.arraycopy(state[i], 0, tarr[i], 0, 4);
		}
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[i][j] = inverseMcLookup(tarr, inverseGalois, i, j);
			}
		}
	}
	// Left rotates the array by given number of times
	public static int[] leftRotate(int[] arr, int times) {
	        if (times % 4 == 0) {
	            return arr;
	        }
	        while (times > 0) {
	            int temp = arr[0];
	            for (int i = 0; i < arr.length - 1; i++) {
	                arr[i] = arr[i + 1];
	            }
	            arr[arr.length - 1] = temp;
	            --times;
	        }
	        return arr;
	}
	// Right rotates the array by given number of times
	public static int[] rightRotate(int[] arr, int times) {
		if (arr.length == 0 || arr.length == 1 || times % 4 == 0) {
			return arr;
		}
		while (times > 0) {
			int temp = arr[arr.length - 1];
			for (int i = arr.length - 1; i > 0; i--) {
				arr[i] = arr[i - 1];
			}
			arr[0] = temp;
			--times;
		}
		return arr;
	}
	// Performs mix column operation on each element
	public static int mcLookup(int[][] arr, int[][] g, int i, int j)
	{
		int mcsum = 0;
		for (int k = 0; k < 4; k++) {
			int a = g[i][k];
			int b = arr[k][j];
			mcsum ^= mcCalc(a, b);
		}
		return mcsum;
	}
	 // Helper method for mcLookup, uses values from look-up tables
	public static int mcCalc(int a, int b) {
		if (a == 1) {
			return b;
		} else if (a == 2) {
			return MCTables.mc2[b / 16][b % 16];
		} else if (a == 3) {
			return MCTables.mc3[b / 16][b % 16];
		}
		return 0;
	}
	// Reverse mix column operation on each element 
	public static int inverseMcLookup(int[][] arr, int[][] iGalois, int i, int j) {
		int mcsum = 0;
		for (int k = 0; k < 4; k++) {
			int a = iGalois[i][k];
			int b = arr[k][j];
			mcsum ^= inverseMcCalc(a, b);
		}
		return mcsum;
	}
	// Helper method for inverseMcLookup, uses values from look-up tables
	public static int inverseMcCalc(int a, int b) {
		if (a == 9) {
			return MCTables.mc9[b / 16][b % 16];
		} else if (a == 0xb) {
			return MCTables.mc11[b / 16][b % 16];
		} else if (a == 0xd) {
			return MCTables.mc13[b / 16][b % 16];
		} else if (a == 0xe) {
			return MCTables.mc14[b / 16][b % 16];
		}
		return 0;
	}
	// Key scheduling to expand the key into round keys
	public static int[][] keySchedule(String key) {
		int binkeysize = key.length() * 4;
		// Size of key scheduling will be based on the binary size of the key
		int colsize = binkeysize + 48 - (32 * ((binkeysize / 64) - 2)); 
		//creates the matrix for key scheduling
		int[][] keyMatrix = new int[4][colsize / 4]; 
		int rconpPointer = 1;
		int[] t = new int[4];
		final int keycounter = binkeysize / 32;
		int k;
		// The first 1 128-bit key set of 4x4 matrices are filled with the key
		for (int i = 0; i < keycounter; i++) 
		{
			for (int j = 0; j < 4; j++) {
				keyMatrix[j][i] = Integer.parseInt(key.substring((8 * i) + (2 * j), (8 * i) + (2 * j + 2)), 16);
			}
		}
		int keypoint = keycounter;
		while (keypoint < (colsize / 4)) {
			int temp = keypoint % keycounter;
			if (temp == 0) {
				for (k = 0; k < 4; k++) {
					t[k] = keyMatrix[k][keypoint - 1];
				}
				t = schedule_core(t, rconpPointer++);
				for (k = 0; k < 4; k++) {
					keyMatrix[k][keypoint] = t[k] ^ keyMatrix[k][keypoint - keycounter];
				}
				keypoint++;
			} else if (temp == 4) {
				for (k = 0; k < 4; k++) {
					int hex = keyMatrix[k][keypoint - 1];
					keyMatrix[k][keypoint] = sbox[hex / 16][hex % 16] ^ keyMatrix[k][keypoint - keycounter];
				}
				keypoint++;
			} else {
				int ktemp = keypoint + 3;
				while (keypoint < ktemp) {
					for (k = 0; k < 4; k++) {
						keyMatrix[k][keypoint] = keyMatrix[k][keypoint - 1] ^ keyMatrix[k][keypoint - keycounter];
					}
					keypoint++;
				}
			}
		}
		return keyMatrix;
	}
	// For every (binary key size / 32)th column in the expanded key, compute a special column
    // using sbox and an XOR of the rcon number with the first element in the passed array
	public static int[] schedule_core(int[] in, int rconPointer) {
		in = leftRotate(in, 1);
		int hex;
		for (int i = 0; i < in.length; i++) {
			hex = in[i];
			in[i] = sbox[hex / 16][hex % 16];
		}
		in[0] ^= rcon[rconPointer];
		return in;
	}
	// String to hex conversion
	public static String stringToHex(String line) throws UnsupportedEncodingException {
	    return String.format("%032x", new BigInteger(1, line.getBytes("UTF-8")));
	}
	// Hex to String conversion
	public static String hexToString(String arg) {        
	    String str = "";
	    for(int i=0;i<arg.length();i+=2) {
	        String s = arg.substring(i, (i + 2));
	        int decimal = Integer.parseInt(s, 16);
	        str = str + (char) decimal;
	    }       
	    return str;
	}
	// Logs time
	public static long logTime(long startTime, long endTime) {
		return (endTime - startTime);///1000000;
	}
	// Calculates average time for 100 runs
	public static long averageTime(long[] time) {
		long avg = 0;
		for(int i=0; i<time.length; i++) {
			avg = avg + time[i];
		}
		avg = avg/time.length;
		return avg/1000;
	}
	
	public static void main(String[] args) {
		try{
			long time[] = new long[10000];
			iv = stringToHex(iv);
			//System.out.println("Iv: "+iv);
			if (args[0].equalsIgnoreCase("e")) {
				for(int j=0; j<10000; j++) {
					BufferedReader plainText = new BufferedReader(new FileReader("plain.txt"));
					BufferedReader keyFile = new BufferedReader(new FileReader("key.txt"));
					BufferedWriter encFile = new BufferedWriter(new FileWriter("EncyptedFile.enc")) ;
					String line;
					key = keyFile.readLine();
					key = stringToHex(key);
					//System.out.println("Key: "+key);
					// 10 rounds for 128 bit key
					int rounds = 10;
					// 4x4 Matrix
					int[][] state;
					int[][] ivMatrix = new int[4][4];
					// Log time
					long startTime = System.nanoTime();
					int[][] keyMatrix = keySchedule(key);
					// Convert iv to Matrix
					stringToMatrix(iv, ivMatrix);
					line = plainText.readLine();
					line = stringToHex(line);
					//System.out.println("plainText: "+line);
					while(line != null) {
						state = new int[4][4];
						// Convert plain text to state matrix
						stringToMatrix(line,state);
						// Feeding initial vector
						addRoundKey(state, ivMatrix);
						// Initial round, add round key with key from first round of key expansion
						addRoundKey(state, subKey(keyMatrix, 0));
						for(int i=1; i<rounds; i++) {
							// Sub-Bytes
							subBytes(state);
							// Shift-Rows
							shiftRows(state);
							// Mix columns
							mixColumns(state);
							addRoundKey(state, subKey(keyMatrix, i));
						}
						// Final round
						subBytes(state);
						shiftRows(state);
						addRoundKey(state, subKey(keyMatrix, rounds));
						// Feed cipher as iv to next block
						ivMatrix = state;
						encFile.write(matrixToString(state));
						encFile.flush();
						line = plainText.readLine();
					}
					// Calculate time taken
					long endTime = System.nanoTime();
					long timeTaken = logTime(startTime, endTime);
					time[j] = timeTaken;
					encFile.close();
					plainText.close();
					keyFile.close();
				}
				BufferedReader plainText = new BufferedReader(new FileReader("plain.txt"));
				System.out.println("Plain text: "+plainText.readLine());
				BufferedReader cipherText = new BufferedReader(new FileReader("EncyptedFile.enc"));
				System.out.println("Cipher text: "+cipherText.readLine());
				plainText.close();
				cipherText.close();
				System.out.println("KeyHex: "+key);
				System.out.println("Key:"+hexToString(key));
				System.out.println("Time taken for encryption: "+averageTime(time) +" ms");
				System.out.println("Encryption completed!");
			}
			else if(args[0].equalsIgnoreCase("d")) {
				for(int j=0; j<10000; j++) {
					BufferedReader cipherText = new BufferedReader(new FileReader("EncyptedFile.enc"));
					BufferedReader keyFile = new BufferedReader(new FileReader("key.txt"));
					BufferedWriter decFile = new BufferedWriter(new FileWriter("DecryptedFile.dec")) ;
					String line;
					key = keyFile.readLine();
					key = stringToHex(key);
					//System.out.println("Key: "+key);
					// 10 rounds for 128 bit key
					int rounds = 10;
					// 4x4 Matrix
					int[][] state;
					int[][] ivMatrix = new int[4][4];
					int[][] nextIv = new int[4][4];
					// Log time
					long startTime = System.nanoTime();
					int[][] keyMatrix = keySchedule(key);
					// Convert iv to Matrix
					stringToMatrix(iv, ivMatrix);
					line = cipherText.readLine();
					while(line != null) {
						state = new int[4][4];
						// Convert cipher text to state matrix
						stringToMatrix(line, state);
						// Copy state to nextIv for next block, temp storage
						copyToNextIv(nextIv, state);
						// Initial round
						addRoundKey(state, subKey(keyMatrix, rounds));
						for (int i = rounds - 1; i > 0; i--) {
							// Inverse sub shift rows
							inverseShiftRows(state);
							// Inverse sub bytes
							inverseSubBytes(state);
							addRoundKey(state, subKey(keyMatrix, i));
							// Inverse mix columns
							inverseMixColumns(state);
						}
						// Final round
						inverseShiftRows(state);
						inverseSubBytes(state); 
						addRoundKey(state, subKey(keyMatrix, 0));
						addRoundKey(state, ivMatrix);
						// Copy state to nextIv for next block
						copyToNextIv(ivMatrix,nextIv);
						String str = hexToString(matrixToString(state));
						decFile.write(str);
						decFile.flush();
						line = cipherText.readLine();
					}
					// Calculate time taken
					long endTime = System.nanoTime();
					long timeTaken = logTime(startTime, endTime);
					time[j] = timeTaken;
					decFile.close();
					cipherText.close();
					keyFile.close();
				}
				BufferedReader cipherText = new BufferedReader(new FileReader("EncyptedFile.enc"));
				System.out.println("Cipher text: "+cipherText.readLine());
				BufferedReader decFile = new BufferedReader(new FileReader("DecryptedFile.dec")) ;
				System.out.println("Plain text: "+decFile.readLine());
				cipherText.close();
				decFile.close();
				System.out.println("KeyHex: "+key);
				System.out.println("Key:"+hexToString(key));
				System.out.println("Time taken for decryption: "+averageTime(time) +" ms");
				System.out.println("Decryption completed!");
			}
			else {
				throw new Exception("Commands available: e|d");
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		
	}

}
