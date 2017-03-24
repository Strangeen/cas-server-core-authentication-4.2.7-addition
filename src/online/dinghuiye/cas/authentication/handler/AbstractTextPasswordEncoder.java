package online.dinghuiye.cas.authentication.handler;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.lang3.StringUtils;
import org.jasig.cas.authentication.handler.PasswordEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public abstract class AbstractTextPasswordEncoder implements PasswordEncoder {

	protected static final Logger LOGGER = LoggerFactory.getLogger(Base64TextPasswordEncoder.class);
	
	@Value("${cas.authn.password.encoding.alg:}")
	protected String encodingAlgorithm;
	
	@Value("${cas.authn.password.encoding.char:}")
	protected String characterEncoding;
	
	@Override
	public String encode(final String password) {
		if (password == null) {
			return null;
		}
		
		if (StringUtils.isBlank(this.encodingAlgorithm)) {
			LOGGER.warn("No encoding algorithm is defined. Password cannot be encoded; Returning null");
			return null;
		}
		
		try {
			final MessageDigest messageDigest = MessageDigest.getInstance(this.encodingAlgorithm);
			
			final String encodingCharToUse = StringUtils.isNotBlank(this.characterEncoding)
												? this.characterEncoding : Charset.defaultCharset().name();
			
			LOGGER.warn("Using {} as the character encoding algorithm to update the digest", encodingCharToUse);
			messageDigest.update(password.getBytes(encodingCharToUse));
			
			final byte[] digest = messageDigest.digest();
			
			return getFormattedText(digest);
		} catch (final NoSuchAlgorithmException e) {
			throw new SecurityException(e);
		} catch (final UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
		
	public void setCharacterEncoding(final String characterEncoding) {
		this.characterEncoding = characterEncoding;
	}
	
	/**
	 * Takes the raw bytes from the digest and formats them correct.
	 *
	 * @param bytes the raw bytes from the digest.
	 * @return the formatted bytes by Base64.
	 * @throws UnsupportedEncodingException 
	 */
	protected abstract String getFormattedText(final byte[] bytes) throws UnsupportedEncodingException;
}
