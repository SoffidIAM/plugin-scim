package com.soffid.iam.sync.agent.scim;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class Utils {

	public static String URLEncode(String path) {
		try {
			return URLEncoder.encode(path, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e) {
			return path;
		}
	}
	
	public static String URLDecode(String path) {
		try {
			return URLDecoder.decode(path, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e) {
			return path;
		}
	}
}
