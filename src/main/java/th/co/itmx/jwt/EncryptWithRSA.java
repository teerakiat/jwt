package th.co.itmx.jwt;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

public class EncryptWithRSA {

    public static void encrypt(String content) throws Exception {

        String x509CertFileName = "D:\\Workspace\\certificate\\bbl_cert.pem";
        String privateKeyFileName = "D:\\Workspace\\certificate\\bbl.p12";


        byte[] x509Cert = Files.readAllBytes(Paths.get(x509CertFileName));

        X509Certificate cert = X509CertUtils.parse(x509Cert);

        KeyStore keyStore = SignWithRSA.loadKeyStorePkcs12(privateKeyFileName, "test123".toCharArray());

        final String alias = keyStore.aliases().nextElement(); // Select the first entry in the key store
//        System.out.println(alias);
//        System.out.println(content);
        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(null));

        RSAPrivateKey privateKey = (RSAPrivateKey) pkEntry.getPrivateKey();

// Compose the JWT claims set
        Date now = new Date();

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .issuer("https://openid.net")
                .subject("alice")
                .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                .expirationTime(new Date(now.getTime() + 1000*60*10)) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .claim("myClaim", content)
                .jwtID(UUID.randomUUID().toString())
                .build();

        System.out.println(jwtClaims.toJSONObject());

// Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

// Create the encrypted JWT object
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

// Create an encrypter with the specified public RSA key
        RSAEncrypter encrypter = new RSAEncrypter( (RSAPublicKey) cert.getPublicKey());

// Do the actual encryption
        jwt.encrypt(encrypter);

// Serialise to JWT compact form
        String jwtString = jwt.serialize();

        System.out.println(jwtString);

// ************ Decrypted : Parse back ************
        jwt = EncryptedJWT.parse(jwtString);

// Create a decrypter with the specified private RSA key
        RSADecrypter decrypter = new RSADecrypter(privateKey);

// Decrypt
        jwt.decrypt(decrypter);

// Retrieve JWT claims
        System.out.println(jwt.getJWTClaimsSet().getIssuer());
        System.out.println(jwt.getJWTClaimsSet().getSubject());
        System.out.println(jwt.getJWTClaimsSet().getAudience().size());
        System.out.println(jwt.getJWTClaimsSet().getExpirationTime());
        System.out.println(jwt.getJWTClaimsSet().getNotBeforeTime());
        System.out.println(jwt.getJWTClaimsSet().getIssueTime());
        System.out.println(jwt.getJWTClaimsSet().getJWTID());
        System.out.println(jwt.getJWTClaimsSet().getClaim("myClaim"));
    }
}
