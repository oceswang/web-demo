package com.github.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RASUtils
{
	private static final String ALGORITHOM = "RSA";
	private static final int KEY_SIZE = 1024;
	private static KeyPair keyPair;
	private static final Provider provider = new BouncyCastleProvider();
	static
	{
		try
		{
			Security.addProvider(provider);
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHOM, provider);
			generator.initialize(KEY_SIZE);
			keyPair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static PublicKey getPublicKey()
	{
		return keyPair.getPublic();
	}

	public static PrivateKey getPrivateKey()
	{
		return keyPair.getPrivate();
	}

	public static String decrypt(String content) throws Exception
	{
		Cipher cipher = Cipher.getInstance("RSA", provider);
		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
		//byte[] raw = new BigInteger(content, 16).toByteArray();
		byte[] raw = hexStringToBytes(content);
		/*
		 * int blockSize = cipher.getBlockSize(); ByteArrayOutputStream bout =
		 * new ByteArrayOutputStream(64); int j = 0; while (raw.length - j *
		 * blockSize > 0) { bout.write(cipher.doFinal(raw, j * blockSize,
		 * blockSize)); j++; } return new String(bout.toByteArray());
		 */
		return new String(cipher.doFinal(raw));
	}

	public static byte[] hexStringToBytes(String hexString)
	{
		if (hexString == null || hexString.equals(""))
		{
			return null;
		}
		hexString = hexString.toUpperCase();
		int length = hexString.length() / 2;
		char[] hexChars = hexString.toCharArray();
		byte[] d = new byte[length];
		for (int i = 0; i < length; i++)
		{
			int pos = i * 2;
			d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
		}
		return d;
	}

	private static byte charToByte(char c)
	{
		return (byte) "0123456789ABCDEF".indexOf(c);
	}

}
