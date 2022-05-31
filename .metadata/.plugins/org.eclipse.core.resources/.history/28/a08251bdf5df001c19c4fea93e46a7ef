package encoding;

public class Url_encoding {

	public String url_encorder(String url, String key, int timeout, int skip_path, int except_file) {
		try {
			byte[] cipher_key_e;
			Utilities utilities = new Utilities();
			Output output = utilities.input_parser(url, timeout, skip_path, except_file);

			SHA256 sha256 = new SHA256();
			cipher_key_e = sha256.encrypt(key);

			AES256 aes256 = new AES256();
			String cipher_text = aes256.encrypt(output.json_string, cipher_key_e);

			utilities.print_result(cipher_text, output);
			String result = output.skiped_path + cipher_text + output.file_name;
			return result;
		} catch (Exception e) {
			e.printStackTrace();
			return "";
		}
	}
}
