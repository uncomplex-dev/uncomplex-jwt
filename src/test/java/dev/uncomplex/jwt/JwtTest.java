package dev.uncomplex.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;


import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 *
 * @author James Thorpe <james@uncomplex.dev>
 */
public class JwtTest {

    public static byte[] shaKey;

    public static byte[] rsaPublicKey;
    public static byte[] rsaPrivateKey;
    public static KeyPairGenerator generator;

    static {
        try {

            // create a token and sha secret key
            byte[] randValue = new byte[64];
            SecureRandom.getInstance("SHA1PRNG").nextBytes(randValue);
            shaKey = randValue;

            // create private and public keys
            generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048, new SecureRandom());
            KeyPair pair = generator.generateKeyPair();
            rsaPublicKey = pair.getPublic().getEncoded();
            rsaPrivateKey = pair.getPrivate().getEncoded();

            System.out.println("--- HS256 Key ---");
            System.out.println(Base64.getUrlEncoder().withoutPadding().encodeToString(shaKey));
            System.out.println("--- RS256 Public Key ---");
            System.out.println(Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPublicKey));
            System.out.println("--- HS256 Private Key ---");
            System.out.println(Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPrivateKey));

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(JwtTest.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public JwtTest() {
    }

    /**
     * Test of decode method, of class Jwt.
     */
    @Test
    public void testEncoding() throws Exception {
        var jwt = JwtBuilderTest.buildJwt();
        var encoded = jwt.encode();
        var decoded = Jwt.decode(encoded);
        JwtBuilderTest.validateJwt(decoded);
    }

    @Test
    public void testSha256() throws Exception {
        var jwt = JwtBuilderTest.buildJwt();
        jwt.sign(Jwt.Algorithm.HS256, shaKey);
        System.out.println(jwt.encode());
        var v = jwt.verify(shaKey);
        assertTrue(v);
    }

    @Test
    public void testSha384() throws Exception {
        var jwt = JwtBuilderTest.buildJwt();
        jwt.sign(Jwt.Algorithm.HS384, shaKey);
        System.out.println(jwt.encode());
        var v = jwt.verify(shaKey);
        assertTrue(v);
    }

    @Test
    public void testSha512() throws Exception {
        var jwt = JwtBuilderTest.buildJwt();
        jwt.sign(Jwt.Algorithm.HS512, shaKey);
        System.out.println(jwt.encode());
        var v = jwt.verify(shaKey);
        assertTrue(v);
    }

    @Test
    public void testRsa256() throws Exception {
        var jwt = JwtBuilderTest.buildJwt();
        jwt.sign(Jwt.Algorithm.RS256, rsaPrivateKey);
        System.out.println(jwt.encode());
        var v = jwt.verify(rsaPublicKey);
        assertTrue(v);
    }

    @Test
    public void testRsa384() throws Exception {
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        rsaPublicKey = pair.getPublic().getEncoded();
        rsaPrivateKey = pair.getPrivate().getEncoded();
        var jwt = JwtBuilderTest.buildJwt();
        jwt.sign(Jwt.Algorithm.RS384, rsaPrivateKey);
        System.out.println(jwt.encode());
        var v = jwt.verify(rsaPublicKey);
        assertTrue(v);
    }

    @Test
    public void testRsa512() throws Exception {
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        rsaPublicKey = pair.getPublic().getEncoded();
        rsaPrivateKey = pair.getPrivate().getEncoded();
        var jwt = JwtBuilderTest.buildJwt();
        jwt.sign(Jwt.Algorithm.RS512, rsaPrivateKey);
        System.out.println(jwt.encode());
        var v = jwt.verify(rsaPublicKey);
        assertTrue(v);
    }

}
