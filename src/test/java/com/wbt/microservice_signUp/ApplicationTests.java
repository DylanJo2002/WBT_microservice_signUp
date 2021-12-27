package com.wbt.microservice_signUp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.wbt.microservice_signUp.utils.Encrytor;

@SpringBootTest
class ApplicationTests {
	
	@Autowired
	Encrytor encryptor;

	@Test
	void contextLoads() throws Exception{
		final String word = "Laura";
		final String encryptedWord = encryptor.encryptWord(word);
		final String decryptedWord = encryptor.decryptWord(encryptedWord);
		assertEquals(word, decryptedWord);
	}

}
