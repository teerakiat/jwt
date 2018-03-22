package th.co.itmx.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

public class SignAndEncryptWithRSA {
    public static void SignAndEncrypt(String content) throws Exception{

        String x509CertFileName = "D:\\Workspace\\certificate\\bbl_cert.pem";
        String privateKeyFileName = "D:\\Workspace\\certificate\\bbl.p12";

        byte[] x509Cert = Files.readAllBytes(Paths.get(x509CertFileName));

        X509Certificate cert = X509CertUtils.parse(x509Cert);

        KeyStore keyStore = SignWithRSA.loadKeyStore(privateKeyFileName, "test123".toCharArray());

        final String alias = keyStore.aliases().nextElement(); // Select the first entry in the key store
//        System.out.println(alias);
//        System.out.println(content);
        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(null));

//        System.out.println(pkEntry);

        RSAPrivateKey privateKey = (RSAPrivateKey) pkEntry.getPrivateKey();

        JWSSigner signer = new RSASSASigner(privateKey);

// Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("ITMX")
                .issuer("https://itmx.co.th")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .claim("myClaim", content)
                .build();
        System.out.println(claimsSet.toJSONObject());

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS512),
                claimsSet);

        signedJWT.sign(signer);
//
//        System.out.println(signedJWT.getPayload());
        System.out.println("============================");

        //Create JWT object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(signedJWT));

        RSAEncrypter encrypter = new RSAEncrypter( (RSAPublicKey) cert.getPublicKey());
        jweObject.encrypt(encrypter);

// Serialise to JWE compact form
        String jweString = jweObject.serialize();
        System.out.println(jweString);

// **************** parse back
        EncryptedJWT jwt = EncryptedJWT.parse(jweString);

// Create a decrypter with the specified private RSA key
        RSADecrypter decrypter = new RSADecrypter(privateKey);

// Decrypt
        jwt.decrypt(decrypter);

        System.out.println("============================");
        System.out.println(jwt.getPayload().toString());
//
//        //*** verify signature
        signedJWT = SignedJWT.parse(jwt.getPayload().toString());
////
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) cert.getPublicKey());
        System.out.println(signedJWT.verify(verifier));
//
//// Retrieve / verify the JWT claims according to the app requirements
        System.out.println(signedJWT.getJWTClaimsSet().getSubject());
        System.out.println(signedJWT.getJWTClaimsSet().getIssuer());
        System.out.println(signedJWT.getJWTClaimsSet().getClaim("myClaim"));
        System.out.println(new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()));
    }
}
