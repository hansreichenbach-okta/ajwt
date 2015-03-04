package io.jsonwebtoken.test;

import org.easymock.EasyMockSupport;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.PrematureJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.TextCodec;

/**
 * Created by hans.reichenbach on 3/3/15.
 */
public class JwtParserTest extends EasyMockSupport {
    //TODO doesn't really follow typical conventions
    //TODO tests are failing because hitting Base64 stub instead of mocking it

    private static final SecureRandom random = new SecureRandom(); //doesn't need to be seeded - just testing
    
    private SigningKeyResolverAdapter signingKeyResolver;

    protected static byte[] randomKey() {
        //create random signing key for testing:
        byte[] key = new byte[64];
        random.nextBytes(key);
        return key;
    }
    
    @Before
    public void setup() {
        signingKeyResolver = new SigningKeyResolverAdapter();
    }

    @Test
    public void testSetDuplicateSigningKeys() {

        byte[] keyBytes = randomKey();

        SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256");

        String compact = Jwts.builder().setPayload("Hello World!").signWith(SignatureAlgorithm.HS256, keyBytes).compact();

        try {
            Jwts.parser().setSigningKey(keyBytes).setSigningKey(key).parse(compact);
            Assert.fail();
        } catch (IllegalStateException ise) {
            Assert.assertEquals(ise.getMessage(), "A key object and key bytes cannot both be specified. Choose either.");
        }
    }

    @Test
    public void testIsSignedWithNullArgument() {
        Assert.assertFalse(Jwts.parser().isSigned(null));
    }

    @Test
    public void testIsSignedWithJunkArgument() {
        Assert.assertFalse(Jwts.parser().isSigned("hello"));
    }

    @Test
    public void testParseWithJunkArgument() {

        String junkPayload = "{;aklsjd;fkajsd;fkjasd;lfkj}";

        String bad = TextCodec.BASE64.encode("{\"alg\":\"none\"}") + "." +
                TextCodec.BASE64.encode(junkPayload) + ".";

        try {
            Jwts.parser().parse(bad);
            Assert.fail();
        } catch (MalformedJwtException expected) {
            Assert.assertEquals(expected.getMessage(), "Unable to read JSON value: " + junkPayload);
        }
    }

    @Test
    public void testParseJwsWithBadAlgHeader() {

        String badAlgorithmName = "whatever";

        String header = "{\"alg\":\"" + badAlgorithmName + "\"}";

        String payload = "{\"subject\":\"Joe\"}";

        String badSig = ";aklsjdf;kajsd;fkjas;dklfj";

        String bad = TextCodec.BASE64.encode(header) + "." +
                TextCodec.BASE64.encode(payload) + "." +
                TextCodec.BASE64.encode(badSig);

        try {
            Jwts.parser().setSigningKey(randomKey()).parse(bad);
            Assert.fail();
        } catch (SignatureException se) {
            Assert.assertEquals(se.getMessage(), "Unsupported signature algorithm \"" + badAlgorithmName + "\"");
        }
    }

    @Test
    public void testParseWithInvalidSignature() {

        String header = "{\"alg\":\"HS256\"}";

        String payload = "{\"subject\":\"Joe\"}";

        String badSig = ";aklsjdf;kajsd;fkjas;dklfj";

        String bad = TextCodec.BASE64.encode(header) + "." +
                TextCodec.BASE64.encode(payload) + "." +
                TextCodec.BASE64.encode(badSig);

        try {
            Jwts.parser().setSigningKey(randomKey()).parse(bad);
            Assert.fail();
        } catch (SignatureException se) {
            Assert.assertEquals(se.getMessage(), "JWT signature does not match locally computed " +
                    "signature. JWT validity cannot be asserted and should not be trusted.");
        }

    }

    @Test
    public void testParsePlaintextJwsWithIncorrectAlg() {

        String header = "{\"alg\":\"none\"}";

        String payload = "{\"subject\":\"Joe\"}";

        String badSig = ";aklsjdf;kajsd;fkjas;dklfj";

        String bad = TextCodec.BASE64.encode(header) + "." +
                TextCodec.BASE64.encode(payload) + "." +
                TextCodec.BASE64.encode(badSig);

        try {
            Jwts.parser().setSigningKey(randomKey()).parse(bad);
            Assert.fail();
        } catch (MalformedJwtException se) {
            Assert.assertEquals(se.getMessage(), "JWT string has a digest/signature, but the header " +
                    "does not reference a valid signature algorithm.");
        }

    }

    @Test
    public void testParseWithBase64EncodedSigningKey() {
        byte[] key = randomKey();
        String base64Encodedkey = TextCodec.BASE64.encode(key);
        String payload = "Hello world!";

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256,
                base64Encodedkey).compact();

        Assert.assertTrue(Jwts.parser().isSigned(compact));

        Jwt jwt = Jwts.parser().setSigningKey(base64Encodedkey).parse(compact);

        Assert.assertEquals(jwt.getBody(), payload);
    }

    @Test
    public void testParseWithExpiredJwt() {

        Date exp = new Date(System.currentTimeMillis() - 1000);

        String compact = Jwts.builder().setSubject("Joe").setExpiration(exp).compact();

        try {
            Jwts.parser().parse(compact);
        } catch (ExpiredJwtException e) {
            Assert.assertTrue(e.getMessage().startsWith("JWT expired at "));
        }
    }

    @Test
    public void testParseWithPrematureJwt() {

        Date nbf = new Date(System.currentTimeMillis() + 100000);

        String compact = Jwts.builder().setSubject("Joe").setNotBefore(nbf).compact();

        try {
            Jwts.parser().parse(compact);
        } catch (PrematureJwtException e) {
            Assert.assertTrue(e.getMessage().startsWith("JWT must not be accepted before "));
        }
    }

    // ========================================================================
    // parsePlaintextJwt tests
    // ========================================================================

    @Test
    public void testParsePlaintextJwt() {

        String payload = "Hello world!";

        String compact = Jwts.builder().setPayload(payload).compact();

        Jwt<Header,String> jwt = Jwts.parser().parsePlaintextJwt(compact);

        Assert.assertEquals(jwt.getBody(), payload);
    }

    @Test
    public void testParsePlaintextJwtWithClaimsJwt() {

        String compact = Jwts.builder().setSubject("Joe").compact();

        try {
            Jwts.parser().parsePlaintextJwt(compact);
            Assert.fail();
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Unsigned Claims JWTs are not supported.");
        }
    }

    @Test
    public void testParsePlaintextJwtWithPlaintextJws() {

        String payload = "Hello world!";

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, randomKey()).compact();

        try {
            Jwts.parser().parsePlaintextJws(compact);
            Assert.fail();
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Signed JWSs are not supported.");
        }
    }

    @Test
    public void testParsePlaintextJwtWithClaimsJws() {

        String compact = Jwts.builder().setSubject("Joe").signWith(SignatureAlgorithm.HS256, randomKey()).compact();

        try {
            Jwts.parser().parsePlaintextJws(compact);
            Assert.fail();
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Signed JWSs are not supported.");
        }
    }

    // ========================================================================
    // parseClaimsJwt tests
    // ========================================================================

    @Test
    public void testParseClaimsJwt() {

        String subject = "Joe";

        String compact = Jwts.builder().setSubject(subject).compact();

        Jwt<Header,Claims> jwt = Jwts.parser().parseClaimsJwt(compact);

        Assert.assertEquals(jwt.getBody().getSubject(), subject);
    }

    @Test
    public void testParseClaimsJwtWithPlaintextJwt() {

        String payload = "Hello world!";

        String compact = Jwts.builder().setPayload(payload).compact();

        try {
            Jwts.parser().parseClaimsJwt(compact);
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Unsigned plaintext JWTs are not supported.");
        }
    }

    @Test
    public void testParseClaimsJwtWithPlaintextJws() {

        String payload = "Hello world!";

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, randomKey()).compact();

        try {
            Jwts.parser().parseClaimsJwt(compact);
            Assert.fail();
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Signed JWSs are not supported.");
        }
    }

    @Test
    public void testParseClaimsJwtWithClaimsJws() {

        String compact = Jwts.builder().setSubject("Joe").signWith(SignatureAlgorithm.HS256, randomKey()).compact();

        try {
            Jwts.parser().parseClaimsJwt(compact);
            Assert.fail();
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Signed JWSs are not supported.");
        }
    }

    @Test
    public void testParseClaimsJwtWithExpiredJwt() {

        long nowMillis = System.currentTimeMillis();
        //some time in the past:
        Date exp = new Date(nowMillis - 1000);

        String compact = Jwts.builder().setSubject("Joe").setExpiration(exp).compact();

        try {
            Jwts.parser().parseClaimsJwt(compact);
            Assert.fail();
        } catch (ExpiredJwtException e) {
            Assert.assertTrue(e.getMessage().startsWith("JWT expired at "));
        }
    }

    @Test
    public void testParseClaimsJwtWithPrematureJwt() {

        Date nbf = new Date(System.currentTimeMillis() + 100000);

        String compact = Jwts.builder().setSubject("Joe").setNotBefore(nbf).compact();

        try {
            Jwts.parser().parseClaimsJwt(compact);
        } catch (PrematureJwtException e) {
            Assert.assertTrue(e.getMessage().startsWith("JWT must not be accepted before "));
        }
    }

    // ========================================================================
    // parsePlaintextJws tests
    // ========================================================================

    @Test
    public void testParsePlaintextJws() {

        String payload = "Hello world!";

        byte[] key = randomKey();

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, key).compact();

        Jwt<Header,String> jwt = Jwts.parser().setSigningKey(key).parsePlaintextJwt(compact);

        Assert.assertEquals(jwt.getBody(), payload);
    }

    @Test
    public void testParsePlaintextJwsWithPlaintextJwt() {

        String payload = "Hello world!";

        byte[] key = randomKey();

        String compact = Jwts.builder().setPayload(payload).compact();

        try {
            Jwts.parser().setSigningKey(key).parsePlaintextJws(compact);
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Unsigned plaintext JWTs are not supported.");
        }
    }

    @Test
    public void testParsePlaintextJwsWithClaimsJwt() {

        String subject = "Joe";

        byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(subject).compact();

        try {
            Jwts.parser().setSigningKey(key).parsePlaintextJws(compact);
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Unsigned Claims JWTs are not supported.");
        }
    }

    @Test
    public void testParsePlaintextJwsWithClaimsJws() {

        String subject = "Joe";

        byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact();

        try {
            Jwts.parser().setSigningKey(key).parsePlaintextJws(compact);
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Signed Claims JWSs are not supported.");
        }
    }

    // ========================================================================
    // parseClaimsJws tests
    // ========================================================================

    @Test
    public void testParseClaimsJws() {

        String sub = "Joe";

        byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(sub).signWith(SignatureAlgorithm.HS256, key).compact();

        Jws<Claims> jws = Jwts.parser().setSigningKey(key).parseClaimsJws(compact);

        Assert.assertEquals(jws.getBody().getSubject(), sub);
    }

    @Test
    public void testParseClaimsJwsWithExpiredJws() {

        byte[] key = randomKey();

        long nowMillis = System.currentTimeMillis();
        //some time in the past:
        Date exp = new Date(nowMillis - 1000);

        String compact = Jwts.builder().setSubject("Joe").signWith(SignatureAlgorithm.HS256, key).setExpiration(exp).compact();

        try {
            Jwts.parser().parseClaimsJwt(compact);
            Assert.fail();
        } catch (ExpiredJwtException e) {
            Assert.assertTrue(e.getMessage().startsWith("JWT expired at "));
        }
    }

    @Test
    public void testParseClaimsJwsWithPrematureJws() {

        byte[] key = randomKey();

        Date nbf = new Date(System.currentTimeMillis() + 100000);

        String compact = Jwts.builder().setSubject("Joe").setNotBefore(nbf).signWith(SignatureAlgorithm.HS256, key).compact();

        try {
            Jwts.parser().parseClaimsJws(compact);
        } catch (PrematureJwtException e) {
            Assert.assertTrue(e.getMessage().startsWith("JWT must not be accepted before "));
        }
    }

    @Test
    public void testParseClaimsJwsWithPlaintextJwt() {

        String payload = "Hello world!";

        byte[] key = randomKey();

        String compact = Jwts.builder().setPayload(payload).compact();

        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(compact);
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Unsigned plaintext JWTs are not supported.");
        }
    }

    @Test
    public void testParseClaimsJwsWithClaimsJwt() {

        String subject = "Joe";

        byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(subject).compact();

        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(compact);
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Unsigned Claims JWTs are not supported.");
        }
    }

    @Test
    public void testParseClaimsJwsWithPlaintextJws() {

        String subject = "Joe";

        byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact();

        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(compact);
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Signed Claims JWSs are not supported.");
        }
    }

    // ========================================================================
    // parseClaimsJws with signingKey resolver.
    // ========================================================================

    @Test
    public void testParseClaimsWithSigningKeyResolver() {

        String subject = "Joe";

        final byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact();

        SigningKeyResolverAdapter signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return key;
            }
        };

        Jws<Claims> jws = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact);

        Assert.assertEquals(jws.getBody().getSubject(), subject);
    }

    @Test
    public void testParseClaimsWithSigningKeyResolverInvalidKey() {

        String subject = "Joe";

        byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact();

        SigningKeyResolverAdapter signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return randomKey();
            }
        };

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact);
            Assert.fail();
        } catch (SignatureException se) {
            Assert.assertEquals(se.getMessage(), "JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.");
        }
    }

    @Test
    public void testParseClaimsWithSigningKeyResolverAndKey() {

        String subject = "Joe";

        SecretKeySpec key = new SecretKeySpec(randomKey(), "HmacSHA256");

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact();

        SigningKeyResolverAdapter signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return randomKey();
            }
        };

        try {
            Jwts.parser().setSigningKey(key).setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact);
            Assert.fail();
        } catch (IllegalStateException ise) {
            Assert.assertEquals(ise.getMessage(), "A signing key resolver and a key object cannot both be specified. Choose either.");
        }
    }

    @Test
    public void testParseClaimsWithSigningKeyResolverAndKeyBytes() {

        String subject = "Joe";

        byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact();

        SigningKeyResolverAdapter signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return randomKey();
            }
        };

        try {
            Jwts.parser().setSigningKey(key).setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact);
            Assert.fail();
        } catch (IllegalStateException ise) {
            Assert.assertEquals(ise.getMessage(), "A signing key resolver and key bytes cannot both be specified. Choose either.");
        }
    }

    @Test
    public void testParseClaimsWithNullSigningKeyResolver() {

        String subject = "Joe";

        byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact();

        try {
            Jwts.parser().setSigningKeyResolver(null).parseClaimsJws(compact);
            Assert.fail();
        } catch (IllegalArgumentException iae) {
            Assert.assertEquals(iae.getMessage(), "SigningKeyResolver cannot be null.");
        }
    }

    @Test
    public void testParseClaimsWithInvalidSigningKeyResolverAdapter() {

        String subject = "Joe";

        byte[] key = randomKey();

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact();

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact);
            Assert.fail();
        } catch (UnsupportedJwtException ex) {
            Assert.assertEquals(ex.getMessage(), "The specified SigningKeyResolver implementation does not support " +
                    "Claims JWS signing key resolution.  Consider overriding either the " +
                    "resolveSigningKey(JwsHeader, Claims) or resolveSigningKeyBytes(JwsHeader, Claims) method.");
        }
    }

    // ========================================================================
    // parsePlaintextJws with signingKey resolver.
    // ========================================================================

    @Test
    public void testParsePlaintextJwsWithSigningKeyResolverAdapter() {

        String inputPayload = "Hello world!";

        final byte[] key = randomKey();

        String compact = Jwts.builder().setPayload(inputPayload).signWith(SignatureAlgorithm.HS256, key).compact();

        SigningKeyResolverAdapter signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            public byte[] resolveSigningKeyBytes(JwsHeader header, String payload) {
                return key;
            }
        };

        Jws<String> jws = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parsePlaintextJws(compact);

        Assert.assertEquals(jws.getBody(), inputPayload);
    }

    @Test
    public void testParsePlaintextJwsWithSigningKeyResolverInvalidKey() {

        String inputPayload = "Hello world!";

        byte[] key = randomKey();

        String compact = Jwts.builder().setPayload(inputPayload).signWith(SignatureAlgorithm.HS256, key).compact();

        SigningKeyResolverAdapter signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            public byte[] resolveSigningKeyBytes(JwsHeader header, String payload) {
                return randomKey();
            }
        };

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).parsePlaintextJws(compact);
            Assert.fail();
        } catch (SignatureException se) {
            Assert.assertEquals(se.getMessage(), "JWT signature does not match locally computed " +
                    "signature. JWT validity cannot be asserted and should not be trusted.");
        }
    }

    @Test
    public void testParsePlaintextJwsWithInvalidSigningKeyResolverAdapter() {

        String payload = "Hello world!";

        byte[] key = randomKey();

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, key).compact();

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).parsePlaintextJws(compact);
            Assert.fail();
        } catch (UnsupportedJwtException ex) {
            Assert.assertEquals(ex.getMessage(), "The specified SigningKeyResolver implementation does not support plaintext " +
                    "JWS signing key resolution.  Consider overriding either the " +
                    "resolveSigningKey(JwsHeader, String) or resolveSigningKeyBytes(JwsHeader, String) method.");
        }
    }
}
