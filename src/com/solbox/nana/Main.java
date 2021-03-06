package com.solbox.nana;

//import org.json.simple.JSONArray;
//import org.json.simple.JSONObject;

public class Main {
	public static void main(String[] args) {
		try {
			
			String url = "a/b/c/d/file_name";
			String key = "abcdefghi";
			int timeout = 3600;
			int skipDepth = 4;
			boolean isFileNameExcepted = true;
			byte[] cipherKey;
			Facilities facilities = new Facilities();
			
			//json
			//JSONObject json = new JSONObject();
			//json = facilities.jsonGenerator(url, timeout, skipDepth, fileNameExcepted);
			//String jsonString = json.toString();
			//String jsonString = json.toJSONString();
			
			DataSet dataSet = facilities.inputParser(url, timeout, skipDepth, isFileNameExcepted);

			SHA256 sha256 = new SHA256();
			cipherKey = sha256.encrypt(key);

			AES256 aes256 = new AES256();
			String cipherText = aes256.encrypt(dataSet.jsonString, cipherKey);

			facilities.printResult(cipherText, dataSet);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
}
