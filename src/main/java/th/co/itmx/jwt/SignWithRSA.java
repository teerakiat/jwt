package th.co.itmx.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class SignWithRSA {
    public static void sign(String content) throws Exception{
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
                .build();


        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS512),
                claimsSet);

        signedJWT.sign(signer);

        String s = signedJWT.serialize();

        System.out.println(s);

        //verify signature

// On the consumer side, parse the JWS and verify its RSA signature
        signedJWT = SignedJWT.parse(s);

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) cert.getPublicKey());
        System.out.println(signedJWT.verify(verifier));

// Retrieve / verify the JWT claims according to the app requirements
        System.out.println(signedJWT.getJWTClaimsSet().getSubject());
        System.out.println(signedJWT.getJWTClaimsSet().getIssuer());
        System.out.println(new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

    /**
     * Load the KeyStore from the supplied path with the optional password
     *
     * @param keyStorePath     the Key Store path
     * @param keyStorePassword the optional keystore password (empty string must be provided)
     * @return the Key Store
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static KeyStore loadKeyStore(final String keyStorePath, final char[] keyStorePassword) throws
            GeneralSecurityException, IOException {
        final String KEY_STORE_FORMAT = "pkcs12";
        KeyStore keyStore = null;
        InputStream input;
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            keyStore = KeyStore.getInstance(KEY_STORE_FORMAT, BouncyCastleProvider.PROVIDER_NAME);
            input = new FileInputStream(new File(keyStorePath));
            keyStore.load(input, keyStorePassword);
        } catch (NoSuchProviderException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
        return keyStore;
    }
}
