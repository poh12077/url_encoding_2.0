package encoding;

import java.util.Random;
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
		 	
	    	json.put("seq", random.nextInt(100) );
	    	json.put("path", path);
	    	json.put("exp", exp);
	    	
	    	return json;
		  }
	 
	 void input() {
		 
	 }
	 
	 void output() {
		 
	 }
	
}
