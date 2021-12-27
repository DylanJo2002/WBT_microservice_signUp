package com.wbt.microservice_signUp.utils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.cipher.CryptoCipherFactory.CipherProvider;
import org.apache.commons.crypto.utils.Utils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class Encrytor {
	
	@Value("${encryptor.secretkey}")
	private String secretKey;
	private SecretKeySpec key;
	private IvParameterSpec iv;
	private Properties properties;
	private final String transform = "AES/CBC/PKCS5Padding";
	private final int encryptMode = 1;
	private final int decryptMode = 2;
	
	@PostConstruct
	public void ini() {
		key = new SecretKeySpec(getUTF8(secretKey), "AES");
		iv = new IvParameterSpec(getUTF8(secretKey));
		properties = new Properties();
	}
	
	public String encryptWord(String word) throws Exception {
		String encryptedWord = null;
		final byte[] input = getUTF8(word);
		final byte[] output = new byte[32];
		final CryptoCipher cipher = getCipher(encryptMode);
		
		final int updateBytes = cipher.update(input, 0, input.length, output, 0);
		final int finalBytes = cipher.doFinal(input, 0, 0, output, updateBytes);
		
		cipher.close();
		
		encryptedWord =  Base64.encodeBase64String(Arrays.copyOf(output, updateBytes+finalBytes));
		
		return encryptedWord;
	}
	
	public String decryptWord(String word) throws Exception {
		String decryptedWord = null;
		final CryptoCipher decipher = getCipher(decryptMode);
		final byte[] input = Base64.decodeBase64(word);
		final byte[] decoded = new byte[32];
		
		final int finalBytes = decipher.doFinal(input, 0, input.length, decoded, 0);
		
		decryptedWord = new String(Arrays.copyOf(decoded, finalBytes), StandardCharsets.UTF_8);
		
		return decryptedWord;
	}	
	
	public CryptoCipher getCipher(int mode) throws Exception {
		CryptoCipher cipher = null;
		
		switch(mode) {
			case encryptMode -> {
				properties.setProperty(CryptoCipherFactory.CLASSES_KEY, CipherProvider.OPENSSL.getClassName());
				cipher = Utils.getCipherInstance(transform,properties);
				cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			}
			case decryptMode -> {
				properties.setProperty(CryptoCipherFactory.CLASSES_KEY, CipherProvider.JCE.getClassName());
				cipher = Utils.getCipherInstance(transform,properties);
				cipher.init(Cipher.DECRYPT_MODE, key, iv);				
			}
		
		}
		
		return cipher;
	}
	
	public byte[] getUTF8(String word) {
		return word.getBytes(StandardCharsets.UTF_8);
	}
	
	
}
