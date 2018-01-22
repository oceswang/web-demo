package com.github.web;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.github.util.RASUtils;

@RestController
@RequestMapping("rsa")
public class RSAController
{
	@RequestMapping(value="getPublicKey", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public ResponseEntity<Map<String,String>> getPublicKey()
	{
		try
		{
			RSAPublicKey pubKey = (RSAPublicKey)RASUtils.getPublicKey();
			BigInteger exponent = pubKey.getPublicExponent();
			BigInteger modulus = pubKey.getModulus();
			Map<String,String> map = new HashMap<>();
			map.put("modulus", modulus.toString(16));
			map.put("exponent", exponent.toString(16));
			return ResponseEntity.ok().header("Access-Control-Allow-Origin", "*").body(map);
		} catch (Exception e)
		{
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).header("Access-Control-Allow-Origin", "*").build();
		}
	}
	@RequestMapping(value="decrypt", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public ResponseEntity<String> decrypt(String content)
	{
		try
		{
			String result = RASUtils.decrypt(content);
			return ResponseEntity.ok().header("Access-Control-Allow-Origin", "*").body(result);
		} catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).header("Access-Control-Allow-Origin", "*").build();
		}
	}
}
