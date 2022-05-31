package com.solbox.nana;

public class Utilities {

   static public String urlEncorder(String url, String key, int timeout, int skipDepth, boolean isFileNameExcepted) {
		try {
			
			byte[] cipherKey;
			Facilities facilities = new Facilities();
			DataSet dataSet = facilities.inputParser(url, timeout, skipDepth, isFileNameExcepted);

			SHA256 sha256 = new SHA256();
			cipherKey = sha256.encrypt(key);

			AES256 aes256 = new AES256();
			String cipherText = aes256.encrypt(dataSet.jsonString, cipherKey);

			//facilities.printResult(cipherText, dataSet);
			String result = dataSet.skippedPath + cipherText + dataSet.fileName;
			return result;
		} catch (Exception e) {
			e.printStackTrace();
			return "";
		}
	}
}
