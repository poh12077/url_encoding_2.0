package encoding;

import java.util.Random;

import javax.sound.midi.Sequence;

import org.json.simple.JSONObject;

class Output{
	String json_string;
	String skiped_path;
	String file_name;
	
	public Output(String json_string, String skiped_path, String file_name) {
		this.json_string=json_string;
		this.skiped_path = skiped_path;
		this.file_name=file_name;
	}
	
}

public class Utilities {

	  JSONObject json_generator(String url, int timeout, int skip_path, int except_file) {
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
	 
	  Output input_parser(String url, int timeout, int skip_path, int except_file) {
		 	
		    //seq 
		 	Random random = new Random();
	    	int seq=random.nextInt(1000);
		 	//path
		 	String path="/";
		 	String skiped_path="/";
		 	String[] url_array = url.split("/");
		 	String file_name="";
		 	
		 	for(int i=1; i< skip_path+1; i++) {
		 		skiped_path += url_array[i]+"/";
		 	}
		 	for(int i = 1 + skip_path; i < url_array.length-except_file; i++) {
		 		path +=url_array[i]+"/";
		 	}
		 	path = path.substring(0, path.length()-1);
		 	
		 	if(except_file!=0) {
		 		file_name = "/"+ url_array[url_array.length-1];
		 	}
		 	
		 	//exp
		 	long exp = System.currentTimeMillis() / 1000;
		 	exp+=timeout;
		 	
		 	String json_string = "{ \"seq\": " + Integer.toString(seq) +", \"path\": \"" + path + "\", \"exp\": " + Long.toString(exp) +" }";              
	    	
	    	return new Output(json_string, skiped_path, file_name);
		  }
	 
	 
	 void input() {
		 
	 }
	 
	 void print_result(String cipher_text, Output output) {
		 String result= output.skiped_path + cipher_text + output.file_name;
		 
		 System.out.println(output.json_string);
		 System.out.println(output.json_string.length());
		 System.out.println(result);
	 }
	
}
