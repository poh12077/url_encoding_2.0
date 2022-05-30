package encoding;

//import org.json.simple.JSONArray;
//import org.json.simple.JSONObject;

public class Main {
	public static void main(String[] args) {
		try {
			
			String url = "a/b/c/d/file_name";
			String key = "abcdefghi";
			int timeout = 3;
			int skip_path = 1;
			int except_file = 1;
			byte[] cipher_key_e;
			Utilities utilities = new Utilities();
			
			//json
			//JSONObject json = new JSONObject();
			//json = Utilities.json_generator(url, timeout, skip_path, except_file);
			//String json_string = json.toString();
			//String json_string = json.toJSONString();
			
			Output output = utilities.input_parser(url, timeout, skip_path, except_file);

			SHA256 sha256 = new SHA256();
			cipher_key_e = sha256.encrypt(key);

			AES256 aes256 = new AES256();
			String cipher_text = aes256.encrypt(output.json_string, cipher_key_e);

			utilities.print_result(cipher_text, output);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
}
