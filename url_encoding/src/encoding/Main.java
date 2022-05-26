package encoding;

import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.util.Random;

public class Main {
	public static void main(String[] args) throws Exception {

		String url = "/a/b/c/d/file_name";
		String key = "abcdefghi";
		int timeout = 360000;
		int skip_path = 1;
		int except_file = 1;
		byte[] cipher_key_e;
		JSONObject json = new JSONObject();

		//json
		//json = Utilities.json_generator(url, timeout, skip_path, except_file);
		//String json_string = json.toString();
		//String json_string = json.toJSONString();
		
		//json_string
		String json_string = Utilities.json_string_generator(url, timeout, skip_path, except_file); 
		System.out.println(json_string);
		System.out.println(json_string.length());

		SHA256 sha256 = new SHA256();
		cipher_key_e = sha256.encrypt(key);

		AES256 aes256 = new AES256();
		String cipher_text = aes256.encrypt(json_string, cipher_key_e); 
		 
		System.out.println(cipher_text);

	}
}
