package encoding;

import java.util.Random;

import javax.sound.midi.Sequence;

import org.json.simple.JSONObject;

public class Utilities {

	 static JSONObject json_generator(String url, int timeout, int skip_path, int except_file) {
		 	JSONObject json = new JSONObject();
		 	//seq 
		 	Random random = new Random();
	    	
		 	//path
		 	String path="/";
		 	String[] url_array = url.split("/");
		 	for(int i = 1 + skip_path; i < url_array.length-except_file; i++) {
		 		path +=url_array[i]+"/";
		 	}
		 	
		 	//exp
		 	long exp = System.currentTimeMillis() / 1000;
		 	exp+=timeout;
		 	
		 	/*
	    	json.put("seq", random.nextInt(100) );
	    	json.put("path", path);
	    	json.put("exp", exp);
	    	*/
		 	System.out.println(path);
	    	//test
	    	json.put("seq", 1 );
	    	json.put("path", path);
	    	json.put("exp", 1);
	    	
	    	//System.out.println(json.get("path") );
	    	//System.out.println(json );
	    	
	    	return json;
	    	
		  }
	 
	 static String json_string_generator(String url, int timeout, int skip_path, int except_file) {
		 	//seq 
		 	Random random = new Random();
	    	int seq=random.nextInt(100);
		 	//path
		 	String path="/";
		 	String[] url_array = url.split("/");
		 	for(int i = 1 + skip_path; i < url_array.length-except_file; i++) {
		 		path +=url_array[i]+"/";
		 	}
		 	path = path.substring(0, path.length()-1);
		 	//exp
		 	long exp = System.currentTimeMillis() / 1000;
		 	exp+=timeout;
		 	
	    	//test
	    	seq =1;
	    	exp =1;
		 	String json_string = "{ \"seq\": " + Integer.toString(seq) +", \"path\": \"" + path + "\", \"exp\": " + Long.toString(exp) +" }";              
	    	
	    	return json_string;
	    	
		  }
	 
	 
	 
	 
	 void input() {
		 
	 }
	 
	 void output() {
		 
	 }
	
}