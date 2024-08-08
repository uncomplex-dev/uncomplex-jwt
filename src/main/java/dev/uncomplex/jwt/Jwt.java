package dev.uncomplex.jwt;

import dev.uncomplex.json.JsonMap;
import dev.uncomplex.json.JsonNull;
import dev.uncomplex.json.JsonReader;
import dev.uncomplex.json.JsonString;
import dev.uncomplex.json.JsonValue;
import dev.uncomplex.utf8.Utf8Reader;
import dev.uncomplex.utf8.Utf8Writer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author jthorpe
 */
public class Jwt {

    public enum Algorithm {
        NONE,
        HS256,
        HS384,
        HS512,
        RS256,
        RS384,
        RS512
    }

    private static final String ERR_INVALID_TOKEN = "Invalid token";
    private static final Logger LOG = Logger.getLogger(Jwt.class.getName());

    String[] parts = new String[3];
    JsonValue headers = new JsonMap();
    JsonValue claims = new JsonMap();
    byte[] signature = new byte[0];

    public Map<String, JsonValue> headers() {
        return headers.asMap();
    }

    public Map<String, JsonValue> claims() {
        return claims.asMap();
    }

    public JsonValue header(String k) {
        return headers().getOrDefault(k, new JsonNull());
    }

    public JsonValue header(String k, JsonValue deflt) {
        return headers().getOrDefault(k, deflt);
    }

    public JsonValue claim(String k) {
        return claims().getOrDefault(k, new JsonNull());
    }

    public JsonValue claim(String k, JsonValue deflt) {
        return claims().getOrDefault(k, deflt);
    }

    public boolean isExpired() {
        return expiresAt().isBefore(Instant.now());
    }

    public Algorithm algorithm() {
        return Algorithm.valueOf(header("alg").asString());
    }

    public String audience() {
        return claim("aud").asString();
    }

    public String contentType() {
        return header("cty").asString();
    }

    public Instant expiresAt() {
        return Instant.ofEpochSecond(claim("exp").asLong());
    }

    public String id() {
        return claim("jti").asString();
    }

    public Instant issuedAt() {
        return Instant.ofEpochSecond(claim("iat").asLong());
    }

    public String issuer() {
        return claim("iss").asString();
    }

    public String kid() {
        return header("kid").asString();
    }

    public Instant notBefore() {
        return Instant.ofEpochSecond(claim("nbf").asLong());
    }

    public String subject() {
        return claim("sub").asString();
    }

    public String type() {
        return header("typ").asString();
    }

    public static Jwt decode(String jwtString) throws IOException, ParseException {
        Jwt jwt = new Jwt();
        jwt.parts = jwtString.split("\\.", -1);

        if (jwt.parts.length != 3) {
            throw new RuntimeException(ERR_INVALID_TOKEN);
        }
        var h = Base64.getUrlDecoder().decode(jwt.parts[0]);
        var c = Base64.getUrlDecoder().decode(jwt.parts[1]);
        jwt.headers = new JsonReader(new Utf8Reader(new ByteArrayInputStream(h))).read();
        jwt.claims = new JsonReader(new Utf8Reader(new ByteArrayInputStream(c))).read();
        jwt.signature = Base64.getUrlDecoder().decode(jwt.parts[2]);
        return jwt;
    }

    public String encode() {
        buildParts();
        return new StringBuilder()
                .append(parts[0])
                .append('.')
                .append(parts[1])
                .append('.')
                .append(parts[2])
                .toString();
    }

    public boolean verify(byte[] key) {
        try {
            switch (algorithm()) {
                case HS256:
                    return verifyHs(key, "HmacSHA256");
                case HS384:
                    return verifyHs(key, "HmacSHA384");
                case HS512:
                    return verifyHs(key, "HmacSHA512");
                case RS256:
                    return verifyRs(key, "SHA256withRSA");
                case RS384:
                    return verifyRs(key, "SHA384withRSA");
                case RS512:
                    return verifyRs(key, "SHA512withRSA");
                default:
                    return false;
            }
        } catch (Exception ex) {
            return false;
        }
    }

    private boolean verifyHs(byte[] key, String alg) throws IOException {
        try {
            SecretKeySpec skey = new SecretKeySpec(key, alg);
            var mac = Mac.getInstance(alg);
            mac.init(skey);
            mac.update(Utf8Writer.toBytes(parts[0]));
            mac.update(".".getBytes());
            mac.update(Utf8Writer.toBytes(parts[1]));
            byte[] sig = mac.doFinal();
            return Arrays.equals(signature, sig);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            LOG.log(Level.SEVERE, ex.toString(), ex);
            return false;
        }
    }

    public Jwt sign(Algorithm alg, byte[] key) throws Exception {
        try {
            headers().put("alg", new JsonString(alg.toString()));
            buildParts();
            switch (algorithm()) {
                case HS256:
                    return signHs(key, "HmacSHA256");
                case HS384:
                    return signHs(key, "HmacSHA384");
                case HS512:
                    return signHs(key, "HmacSHA512");
                case RS256:
                    return signRs(key, "SHA256withRSA");
                case RS384:
                    return signRs(key, "SHA384withRSA");
                case RS512:
                    return signRs(key, "SHA512withRSA");
            }
            return this;
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, ex.toString(), ex);
            throw new Exception("Error signing JWT", ex);
        }
    }

    private Jwt signHs(byte[] key, String alg) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec skey = new SecretKeySpec(key, alg);
        var mac = Mac.getInstance(alg);
        mac.init(skey);
        mac.update(Utf8Writer.toBytes(parts[0]));
        mac.update(".".getBytes());
        mac.update(Utf8Writer.toBytes(parts[1]));
        signature = mac.doFinal();
        return this;
    }

    private Jwt signRs(byte[] key, String alg) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        var privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(key));
        Signature rsa = Signature.getInstance(alg);
        rsa.initSign(privateKey);
        rsa.update(Utf8Writer.toBytes(parts[0]));
        rsa.update(".".getBytes());
        rsa.update(Utf8Writer.toBytes(parts[1]));
        signature = rsa.sign();
        return this;
    }

    private boolean verifyRs(byte[] key, String alg) throws IOException {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(key));
            Signature rsa = Signature.getInstance(alg);
            rsa.initVerify(publicKey);
            rsa.update(Utf8Writer.toBytes(parts[0]));
            rsa.update(".".getBytes());
            rsa.update(Utf8Writer.toBytes(parts[1]));
            return rsa.verify(signature);
        } catch (SignatureException | InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException ex) {
            LOG.log(Level.SEVERE, ex.toString(), ex);
            return false;
        }
    }

    private void buildParts() {
        var h = headers.toBytes();
        var c = claims.toBytes();
        parts[0] = Base64.getUrlEncoder().withoutPadding().encodeToString(h);
        parts[1] = Base64.getUrlEncoder().withoutPadding().encodeToString(c);
        parts[2] = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }
}
