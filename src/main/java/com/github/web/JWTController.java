package com.github.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@RestController
@RequestMapping("jwt")
public class JWTController
{
	private String secret = "key-galaxyinternet";
	private String issuer = "galaxyinternet";
	
	@RequestMapping(value="getToken", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<String> getToken()
	{
		String token = null;;
		try
		{
			Algorithm algorithm = Algorithm.HMAC256(secret);
			token = JWT.create().withIssuer(issuer)
			.withClaim("id", 1)
			.withClaim("name", "swang")
			.sign(algorithm);
		} catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.NON_AUTHORITATIVE_INFORMATION).build();
		}
		return ResponseEntity.ok("{\"token\":\"" + token + "\"}");
	}
	
	@RequestMapping(value="verify", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<String> verify(@RequestHeader("Authorization") String auth)
	{
		String info = null;
		try
		{
			String token = auth = auth.replace("Bearer ", "");
			Algorithm algorithm = Algorithm.HMAC256(secret);
			JWTVerifier verifier = JWT.require(algorithm)
			    .withIssuer(issuer)
			    .build(); //Reusable verifier instance
			DecodedJWT jwt = verifier.verify(token);
			info = String.format("Type:%s,algorithm :%s, Claim Name:%s", jwt.getType(),jwt.getAlgorithm(),jwt.getClaim("name").asString());
		} catch (Exception e)
		{
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		} 
		return ResponseEntity.ok("{\"info\":\"" + info + "\"}");
	}
	@RequestMapping(value="decode", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<String> decode(@RequestHeader("Authorization") String auth)
	{
		String info = null;
		try
		{
			if(auth != null)
			{
				auth = auth.replace("Bearer ", "");
			}
			DecodedJWT jwt = JWT.decode(auth);
			info = jwt.getClaim("name").asString();
			
		} catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		} 
		return ResponseEntity.ok("{\"info\":\"" + info + "\"}");
	}
}
