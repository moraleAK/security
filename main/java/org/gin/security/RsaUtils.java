package org.gin.security;

import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerValue;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import static org.gin.security.AlgorithmName.RSA;
import static org.gin.security.AlgorithmName.SHA_256_WITH_RSA;

/**
 * RSA 加解密
 * 一般私钥解密，公钥加密
 * 私钥签名，公钥验签
 * @author Gin
 * @since 2018/11/7 11:16
 */
public class RsaUtils {
    static int encryption = 1;
    static int decryption = 2;
    static int PUBLIC = 1;
    static int PRIVATE = 2;


    /**
     * 私钥加密
     * @param originData 待加密字节
     * @param priKey 私钥字节
     *
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encryptByPrivate(byte[] originData, byte[] priKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(RSA);
        PrivateKey privateKey = PKCS8Key.parseKey(new DerValue(priKey));

        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        cipher.update(originData);
        return cipher.doFinal();
    }

    /**
     * 公钥加密
     * @param originData 待加密字节
     * @param pubKey 公钥
     *
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws CertificateException
     */
    public static byte[] encrypt(byte[] originData, byte[] pubKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        Cipher cipher = Cipher.getInstance(RSA);
        PublicKey publicKey = (PublicKey) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pubKey));

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(originData);
        return cipher.doFinal();
    }


    /**
     * 私钥解密
     *
     * @param originData
     * @param priKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decrypt(byte[] originData, byte[] priKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(RSA);
        PrivateKey privateKey = PKCS8Key.parseKey(new DerValue(priKey));
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipher.update(originData);
        return cipher.doFinal();
    }


    /**
     * 公钥解密
     *
     * @param originData
     * @param pubKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws CertificateException
     */
    public static byte[] decryptByPublic(byte[] originData, byte[] pubKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        Cipher cipher = Cipher.getInstance(RSA);
        PublicKey publicKey = (PublicKey) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pubKey));
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        cipher.update(originData);
        return cipher.doFinal();
    }

    /**
     * 私钥签名
     *
     * @param originData
     * @param priKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] sign(byte[] originData, byte[] priKey) throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SHA_256_WITH_RSA);
        PrivateKey privateKey = PKCS8Key.parseKey(new DerValue(priKey));

        signature.initSign(privateKey);
        signature.update(originData);
        return signature.sign();
    }

    /**
     * 公钥验签
     *
     * @param originData
     * @param pubKey
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws SignatureException
     */
    public static boolean verify(byte[] originData, byte[] pubKey) throws InvalidKeyException, NoSuchAlgorithmException, CertificateException, SignatureException {
        Signature signature = Signature.getInstance(SHA_256_WITH_RSA);
        PublicKey publicKey = (PublicKey) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pubKey));

        signature.initVerify(publicKey);
        return signature.verify(pubKey);
    }
}
