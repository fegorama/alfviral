/*
 * Copyright 2015 Fernando González (fegor@fegor.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.fegorsoft.alfresco.security.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class md5 {
	/**
	 * Calculates the md5sum
	 * 
	 * @param url file url
	 * @return md5sum
	 */
	public static String getMD5Sum(URL url) {
		MessageDigest digest = null;
				
		try {
			digest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
			
		byte[] buffer = new byte[8192];
		int read = 0;
		String output = "";

		InputStream is = null;
		
		try {
			is = url.openStream();

			while( (read = is.read(buffer)) > 0) {
				digest.update(buffer, 0, read);
			}		
			byte[] md5sum = digest.digest();
			BigInteger bigInt = new BigInteger(1, md5sum);
			output = bigInt.toString(16);
		}
		catch(IOException e) {
			e.printStackTrace();
		} finally {
			try {
				is.close();
			} catch(IOException e) {
				e.printStackTrace();
			}
		}
			
		return output;
	}
	
	/**
	 * Calculates the md5sum
	 * 
	 * @param String
	 * @return md5sum
	 */
	public static String getMD5Sum(String str) {
		MessageDigest digest = null;
		StringBuffer sbResult = new StringBuffer();
		
		try {
			digest = MessageDigest.getInstance("MD5");
			digest.update(str.getBytes());
			byte[] hash = digest.digest();
			
			for (int i = 0; i < hash.length; i++) {
				if ((0xff & hash[i]) < 0x10) {
					sbResult.append("0" + Integer.toHexString((0xFF & hash[i])));
				} else {
					sbResult.append(Integer.toHexString(0xFF & hash[i]));
				}
			}
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return sbResult.toString();
	}
}

