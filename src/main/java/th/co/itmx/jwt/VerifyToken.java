package th.co.itmx.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class VerifyToken {
    public static void verify(String token) throws Exception{
        String x509CertFileName = "D:\\tmp\\ITMXSIGN065_20181022.cer";

        byte[] x509Cert = Files.readAllBytes(Paths.get(x509CertFileName));

        X509Certificate cert = X509CertUtils.parse(x509Cert);

        JWSObject jwsObject = JWSObject.parse(token);
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) cert.getPublicKey());
        System.out.println(jwsObject.verify(verifier));


    }
}
