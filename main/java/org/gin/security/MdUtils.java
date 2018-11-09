package org.gin.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.gin.security.AlgorithmName.MD5;
import static org.gin.security.AlgorithmName.SHA_1;
import static org.gin.security.AlgorithmName.SHA_256;

/**
 * a simple wrapper of message digest algorithm
 *
 * @author Gin
 * @since 2018/11/7 11:23
 */
public class MdUtils {


    public static byte[] md5(byte[] data){
        return md(MD5, data);
    }


    public static byte[] sha256(byte[] data){
        return md(SHA_256, data);
    }


    public static byte[] sha1(byte[] data){
        return md(SHA_1, data);
    }


    private static byte[] md(String algorithm, byte[] data){
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        return messageDigest.digest(data);
    }

    public static void main(String[] args) {
        String data = "gin";
        System.out.println(HexUtils.byte2hex(md5(data.getBytes())));
        System.out.println(HexUtils.byte2hex(sha1(data.getBytes())));
        System.out.println(HexUtils.byte2hex(sha256(data.getBytes())));
    }
}
