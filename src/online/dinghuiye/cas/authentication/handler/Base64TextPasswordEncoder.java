package online.dinghuiye.cas.authentication.handler;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

import org.springframework.stereotype.Component;

@Component("base64TextPasswordEncoder")
public class Base64TextPasswordEncoder extends AbstractTextPasswordEncoder {

	@Override
	public String getFormattedText(byte[] bytes) throws UnsupportedEncodingException {
		return new String(Base64.getEncoder().encode(bytes), this.characterEncoding);
	}
}
