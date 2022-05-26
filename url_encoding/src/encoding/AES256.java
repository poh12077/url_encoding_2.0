package encoding;


import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES256 {
	 public static String alg = "AES/CBC/PKCS5Padding";
	   // private final String key = "01234567890123456789012345678901";
	   // private final String iv = key.substring(0, 16); // 16byte
	    //private final String iv = "0000000000000000"; // 16byte
	    private final byte[] iv = new byte[16];
	    
	    public String encrypt(String text, byte[] key) throws Exception {
	        Cipher cipher = Cipher.getInstance(alg);
	        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
	        //IvParameterSpec ivParamSpec = new IvParameterSpec(iv.getBytes());
	        IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamSpec);

	        byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
	       // return Base64.getEncoder().encodeToString(encrypted);
	        return Base64.getUrlEncoder().withoutPadding().encodeToString( encrypted );
	    }

	    public String decrypt(String cipherText, byte[] key) throws Exception {
	        Cipher cipher = Cipher.getInstance(alg);
	        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
	      //  IvParameterSpec ivParamSpec = new IvParameterSpec(iv.getBytes());
	        IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
	        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);

	        byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
	        byte[] decrypted = cipher.doFinal(decodedBytes);
	        return new String(decrypted, "UTF-8");
	    }
}
