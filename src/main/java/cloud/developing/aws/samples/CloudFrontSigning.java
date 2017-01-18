package cloud.developing.aws.samples;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

import org.jets3t.service.security.EncryptionUtil;

import com.amazonaws.services.cloudfront.CloudFrontUrlSigner;

/**
 * @author asmolnik
 *
 */
public class CloudFrontSigning {

	public static void main(String[] args) throws Exception {
		Path pathToPem = Paths.get(System.getProperty("pathToPem"));
		// Must be defined for CF using the root credentials
		String keyId = System.getProperty("keyId");
		String distribution = System.getProperty("distribution");

		final byte[] derKey;
		try (InputStream is = Files.newInputStream(pathToPem)) {
			derKey = EncryptionUtil.convertRsaPemToDer(is);
		}

		PrivateKey pk = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(derKey));
		String url = CloudFrontUrlSigner.getSignedURLWithCannedPolicy("https://" + distribution + ".cloudfront.net/a.txt", keyId, pk,
				new Date(System.currentTimeMillis() + 1000L * 15));
		System.out.println(url);
	}

}
