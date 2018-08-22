package org.irmacard.api.common;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import io.jsonwebtoken.*;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.util.GsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Type;
import java.security.Key;
import java.util.Calendar;
import java.util.Map;

/**
 * A JWT parser for incoming issuer or service provider requests.
 */
@SuppressWarnings("unused")
public class JwtParser <T> {
	private static Logger logger = LoggerFactory.getLogger(JwtParser.class);

	private SigningKeyResolver keyResolver;
	private Key key;
	private long maxAge;
	private boolean allowUnsigned;
	private String subject;
	private String field;
	private Type clazz;

	private String jwt;

	private Claims claims;
	private Header header;
	private T payload;
	private boolean authenticated = false;

	private static Gson gson;

	/**
	 * Construct a new parser.
	 * @param allowUnsigned If unsigned JWT's should be allowed
	 * @param clazz Class of the request that will be present in the JWT's payload
	 * @param maxAge maximum age that the JWT may have
	 */
	public JwtParser(Class<T> clazz, boolean allowUnsigned, int maxAge) {
		this.maxAge = maxAge;
		this.allowUnsigned = allowUnsigned;
		this.clazz = clazz;

		try {
			// The following gets the public final static strings T.JWT_SUBJECT and T.JWT_REQUEST_KEY.
			this.subject = (String) clazz.getField("JWT_SUBJECT").get(null);
			this.field = (String) clazz.getField("JWT_REQUEST_KEY").get(null);
		} catch (IllegalAccessException|NoSuchFieldException e) {
			throw new RuntimeException(e);
		}
	}

	public JwtParser(Type clazz, boolean allowUnsigned, long maxAge, String subject, String field) {
		this.clazz = clazz;
		this.allowUnsigned = allowUnsigned;
		this.maxAge = maxAge;
		this.subject = subject;
		this.field = field;
	}

	/**
	 * Parse the given JWT.
	 */
	public JwtParser<T> parseJwt(String jwt) {
		this.jwt = jwt;

		claims = getClaims();
		payload = parseClaims(claims);

		return this;
	}

	private void parseSignedClaims() {
		// Hmm, got class name clash here, perhaps we should rename
		io.jsonwebtoken.JwtParser parser = Jwts.parser()
				.requireSubject(subject);

		// Passing null to these setters is not allowed
		if (key != null)
			parser.setSigningKey(key);
		else if (keyResolver != null)
			parser.setSigningKeyResolver(keyResolver);

		Jws<Claims> parsedJwt = parser.parseClaimsJws(jwt);
		header = parsedJwt.getHeader();
		claims = parser.parseClaimsJws(jwt).getBody();

		// If we're here then parseClaimsJws() did not throw an exception, so the signature verified
		authenticated = true;
	}

	private void parseUnsignedClaims() {
		// If the JWT contains two dots, then the final part is a signature that we don't care about
		int i = jwt.lastIndexOf('.');
		if (jwt.indexOf('.') != i) {
			logger.warn("Discarding JWT signature!");
			jwt = jwt.substring(0, i + 1);
		}

		Jwt<Header, Claims> parsedJwt = Jwts.parser()
				.requireSubject(subject)
				.parseClaimsJwt(jwt);

		header = parsedJwt.getHeader();
		claims = parsedJwt.getBody();
	}

	/**
	 * Parse the specified String as a JWT, checking its age, and its signature if necessary.
	 * @return The claims contained in the JWT
	 * @throws ApiException If there was no valid signature but there needed to be;
	 *                      if the JWT was too old; or if the specified string could not be
	 *                      parsed as a JWT
	 */
	public Claims getClaims() throws ApiException {
		if (claims != null)
			return claims;

		try {
			logger.info("Trying signed JWT");
			parseSignedClaims();
		} catch (Exception e) {
			if (allowUnsigned) {
				logger.info("Trying unsigned JWT");
				parseUnsignedClaims();
			} else {
				logger.info("JWT invalid:");
				e.printStackTrace();
				throw new ApiException(ApiError.JWT_INVALID);
			}
		}

		long now = Calendar.getInstance().getTimeInMillis();
		long issued_at = claims.getIssuedAt().getTime();
		if (now - issued_at > maxAge)
			throw new ApiException(ApiError.JWT_TOO_OLD, "Max age: " + maxAge + ", was " + (now - issued_at));

		return claims;
	}

	/**
	 * Extract the request from the specified claims.
	 * @throws ApiException if the request could not be deserialized as an instance of T
	 */
	public T parseClaims(Claims claims) throws ApiException {
		// Dirty Hack (tm): we can get a Map from Jwts, but we need an instance of T.
		// But if the structure of the contents of the map exactly matches the fields from T,
		// then we can convert the map to json, and then that json to a T instance.
		Map map = claims.get(field, Map.class);
		String json = getGson().toJson(map);

		try {
			return getGson().fromJson(json, clazz);
		} catch (JsonSyntaxException e) {
			throw new ApiException(ApiError.MALFORMED_ISSUER_REQUEST);
		}
	}

	/**
	 * Get the JWT issuer.
	 * @throws IllegalStateException if no JWT has yet been parsed
	 */
	public String getJwtIssuer() throws IllegalStateException {
		if (payload == null)
			throw new IllegalStateException("No JWT parsed yet");

		if (claims == null)
			return null;

		return claims.getIssuer();
	}

	public String getKeyIdentifier() throws IllegalStateException {
		if (payload == null)
			throw new IllegalStateException("No JWT parsed yet");

		String val = (String) header.get("kid");
		if (val != null)
			return val;
		else
			return getJwtIssuer();
	}

	/**
	 * Return the request that was present in the JWT's payload.
	 * @throws IllegalStateException if no JWT has yet been parsed
	 */
	public T getPayload() throws IllegalStateException {
		if (payload == null)
			throw new IllegalStateException("No JWT parsed yet");

		return payload;
	}

	public void setKeyResolver(SigningKeyResolver keyResolver) {
		this.keyResolver = keyResolver;
	}

	public void setSigningKey(Key key) {
		this.key = key;
	}

	/**
	 * Returns true if the JWT has a signature that has been succesfully verified.
	 * @throws IllegalStateException if no JWT has yet been parsed
	 */
	public boolean isAuthenticated() {
		if (payload == null)
			throw new IllegalStateException("No JWT parsed yet");

		return authenticated;
	}

	private static Gson getGson() {
		return gson != null ? gson : GsonUtil.getGson();
	}

	public static void setGson(Gson gson) {
		JwtParser.gson = gson;
	}
}
