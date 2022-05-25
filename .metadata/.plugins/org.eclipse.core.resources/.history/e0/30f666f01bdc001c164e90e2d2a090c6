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
		String key = "1234";
		int timeout = 60;
		int skip_path = 0;
		int except_file = 0;
		byte[] cipher_key_e;
		JSONObject json = new JSONObject();
		Utilities utilities = new Utilities();

		json = utilities.json_generator(url, timeout, skip_path, except_file);
		String json_string = json.toString();

		SHA256 sha256 = new SHA256();
		cipher_key_e = sha256.encrypt(key);

		AES256 aes256 = new AES256();
		String cipher_text = aes256.encrypt(json_string, cipher_key_e); // System.out.println(cryptogram);
		 

	}
}
