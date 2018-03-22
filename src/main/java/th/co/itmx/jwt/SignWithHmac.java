package th.co.itmx.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;

import java.security.SecureRandom;

public class SignWithHmac {
    public static void sign(String content) throws Exception{

// Generate random 256-bit (32-byte) shared secret
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);

// Create HMAC signer
        JWSSigner signer = new MACSigner(sharedSecret);

// Prepare JWS object with "Hello, world!" payload
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(content));

// Apply the HMAC
        jwsObject.sign(signer);

// To serialize to compact form, produces something like
// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
        String s = jwsObject.serialize();
        System.out.println(s);

// To parse the JWS and verify it, e.g. on client-side
        jwsObject = JWSObject.parse(s);

//        jwsObject.getHeader().getAlgorithm()

        JWSVerifier verifier = new MACVerifier(sharedSecret);

        System.out.println(jwsObject.verify(verifier));

        System.out.println(jwsObject.getPayload().toString());
    }
}
