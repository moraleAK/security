package org.gin.security;

import java.io.*;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

/**
 * @author Gin
 * @since 2018/11/7 20:59
 */
public class CertUtils {
    private static String X509 = "X509";

    public static PublicKey getPublicKey(String path) throws Exception {
        return getPublicKey(new FileInputStream(new File(path)));
    }

    public static PublicKey getPublicKey(byte[] bytes) throws Exception {
        return getPublicKey(new ByteArrayInputStream(bytes));
    }

    private static PublicKey getPublicKey(InputStream in) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(in);
        in.close();
        return certificate.getPublicKey();
    }
}
