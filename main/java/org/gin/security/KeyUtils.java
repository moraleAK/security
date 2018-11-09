package org.gin.security;

import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerValue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * @author Gin
 * @since 2018/11/9 14:00
 */
public class KeyUtils {
    /**
     * 根据公钥字节生成公钥
     *
     * @param pubKey
     * @return
     * @throws CertificateException
     */
    public PublicKey generatePublicKey (byte[] pubKey) throws CertificateException {
        return  (PublicKey) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pubKey));
    }

    /**
     * 根据私钥字节生成私钥
     *
     * @param bytes
     * @return
     * @throws IOException
     */
    public PrivateKey generatePrivateKey(byte[] bytes) throws IOException {
        return PKCS8Key.parseKey(new DerValue(bytes));
    }
}
