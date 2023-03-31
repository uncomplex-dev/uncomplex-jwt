package dev.uncomplex.jwt;

import dev.uncomplex.json.JsonNumber;
import dev.uncomplex.json.JsonValue;
import dev.uncomplex.json.JsonString;
import java.time.Instant;

/**
 *
 * @author jthorpe
 */
public class JwtBuilder {

    private final Jwt jwt = new Jwt();
    
    public JwtBuilder() {
        type("JWT");
        algorithm(Jwt.Algorithm.NONE);
    }

    public JwtBuilder claim(String k, JsonValue v) {
        jwt.claims().put(k, v);
        return this;
    }
    
    public JwtBuilder claim(String k, String v) {
        return claim(k, new JsonString(v));
    }

    public JwtBuilder claim(String k, long v) {
        return claim(k, new JsonNumber(v));
    }

    public JwtBuilder header(String k, JsonValue v) {
        jwt.headers().put(k, v);
        return this;
    }

    public JwtBuilder header(String k, String v) {
        return header(k, new JsonString(v));
    }

  
    public JwtBuilder algorithm(Jwt.Algorithm alg) {
        header("alg", alg.toString());
        return this;
    }
    
    public JwtBuilder audience(String aud) {
        return claim( "aud", aud);
    }
    
    public JwtBuilder contentType(String cty) {
        return header("cty", cty);
    }

    public JwtBuilder expiresAt(Instant exp) {
        return claim("exp", exp.getEpochSecond());
    }
    
    public JwtBuilder id(String id) {
        return claim("jti", id);
    }
    
    public JwtBuilder issuedAt(Instant iat) {
        return claim("iat", iat.getEpochSecond());
    }
    
    public JwtBuilder issuer(String iss) {
        return claim("iss", iss);
    }
    
    public JwtBuilder kid(String kid) {
        return header("kid", kid);
    }

    public JwtBuilder notBefore(Instant nbf) {
        return claim("nbf", nbf.getEpochSecond());
    }
    
    public JwtBuilder subject(String sub) {
        return claim("sub", sub);
    }
    
    public JwtBuilder type(String typ) {
        return header("typ", typ);
    }
    
    public Jwt build() {
        return jwt;
    }
    
}
