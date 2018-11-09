package org.gin.security;

import java.util.Base64;

/**
 * base64编码简单封装
 */
public class Base64Utils {
    public static String encode2String(String data){
        return new String(Base64.getEncoder().encode(data.getBytes()));
    }

    public static String encode2String(byte[] data){
        return new String(Base64.getEncoder().encode(data));
    }

    public static byte[] encode(byte[] data){
        return Base64.getEncoder().encode(data);
    }

    public static byte[] encode(String data){
        return Base64.getEncoder().encode(data.getBytes());
    }

    public static byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public static byte[] decode(byte[] data){
        return Base64.getDecoder().decode(data);
    }

    public static String decode2String(byte[] data){
        return new String(Base64.getDecoder().decode(data));
    }

    public static String decode2String(String data){
        return new String(Base64.getDecoder().decode(data));
    }
}
