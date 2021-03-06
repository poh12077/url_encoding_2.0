package com.solbox.nana;

import java.util.Random;

import org.json.simple.JSONObject;

class DataSet {
	String jsonString;
	String skippedPath;
	String fileName;

	DataSet(String jsonString, String skippedPath, String fileName) throws Exception {
		this.jsonString = jsonString;
		this.skippedPath = skippedPath;
		this.fileName = fileName;
	}

}

class Facilities {

	/*
	 * JSONObject jsonGenerator(String url, int timeout, int skipDepth, int
	 * fileNameExcepted) { JSONObject json = new JSONObject(); //seq Random random = new
	 * Random();
	 * 
	 * //path String path="/"; String[] urlArray = url.split("/"); for(int i = 1 +
	 * skipDepth; i < urlArray.length-fileNameExcepted; i++) { path +=urlArray[i]+"/"; }
	 * 
	 * //exp long exp = System.currentTimeMillis() / 1000; exp+=timeout;
	 * 
	 * 
	 * json.put("seq", random.nextInt(100) ); json.put("path", path);
	 * json.put("exp", exp);
	 * 
	 * System.out.println(path); //test json.put("seq", 1 ); json.put("path", path);
	 * json.put("exp", 1);
	 * 
	 * //System.out.println(json.get("path") ); //System.out.println(json );
	 * 
	 * return json;
	 * 
	 * }
	 */

	DataSet inputParser(String url, int timeout, int skipDepth, boolean isFileNameExcepted) throws Exception {

		// exception handling
		if (timeout <= 0) {
			throw new Exception("timeout must be greater than 0");
		}
		if (url.charAt(0) != '/') {
			url = "/" + url;
		}
		
		// seq
		Random random = new Random();
		int seq = random.nextInt(1000);
		// path
		String path = "/";
		String skippedPath = "/";
		String[] urlArray = url.split("/");
		String fileName = "";
		int fileNameExcepted=0;
		if(isFileNameExcepted) {
			fileNameExcepted=1;
		}
		
		if (skipDepth < 0 ||  urlArray.length-2 < skipDepth ) {
			throw new Exception("skipDepth must be more than 0 and less than path depth ");
		}
		
		for (int i = 1; i < skipDepth + 1; i++) {
			skippedPath += urlArray[i] + "/";
		}
		for (int i = 1 + skipDepth; i < urlArray.length - fileNameExcepted; i++) {
			path += urlArray[i] + "/";
		}
		path = path.substring(0, path.length() - 1);

		if (fileNameExcepted != 0) {
			fileName = "/" + urlArray[urlArray.length - 1];
		}

		// exp
		// second
		long exp = System.currentTimeMillis() / 1000;
		exp += timeout;

		String jsonString = "{ \"seq\": " + Integer.toString(seq) + ", \"path\": \"" + path + "\", \"exp\": "
				+ Long.toString(exp) + " }";

		return new DataSet(jsonString, skippedPath, fileName);
	}

	void printResult(String cipherText, DataSet dataSet) throws Exception {
		String result = dataSet.skippedPath + cipherText + dataSet.fileName;

		System.out.println(dataSet.jsonString);
		System.out.println(dataSet.jsonString.length());
		System.out.println(result);
	}

}
