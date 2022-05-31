package com.solbox.nana;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

 class SHA256 {
	   byte[] encrypt(String text) throws NoSuchAlgorithmException {
	        MessageDigest md = MessageDigest.getInstance("SHA-256");
	        md.update(text.getBytes());

	        //return bytesToHex(md.digest());
	        return md.digest();
	    }

		/*
		 * private String bytesToHex(byte[] bytes) { StringBuilder builder = new
		 * StringBuilder(); for (byte b : bytes) { builder.append(String.format("%02x",
		 * b)); } //return builder.toString(); return new String(builder); }
		 */
}
