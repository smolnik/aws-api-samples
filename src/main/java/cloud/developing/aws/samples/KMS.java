package cloud.developing.aws.samples;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;

/**
 * @author asmolnik
 *
 */
public class KMS {

	public static void main(String[] args) {
		// KMS uses the Advanced Encryption Standard (AES) algorithm in Galois/Counter Mode (GCM),
		// known as AES-GCM. AWS KMS uses this algorithm with 256-bit secret keys

		AWSKMS kms = new AWSKMSClient();
		String keyId = System.getProperty("keyId");
		GenerateDataKeyResult newKey = kms.generateDataKey(new GenerateDataKeyRequest().withKeyId(keyId).withNumberOfBytes(256));

		// use of asReadOnlyBuffer() just to follow recommended in Javadoc practice
		ByteBuffer plainKey = newKey.getPlaintext().asReadOnlyBuffer();
		ByteBuffer encryptedKey = newKey.getCiphertextBlob().asReadOnlyBuffer();

		ByteBuffer decryptedPlainKey = kms.decrypt(new DecryptRequest().withCiphertextBlob(encryptedKey)).getPlaintext().asReadOnlyBuffer();
		System.out.println("plainKey == decryptedPlainKey?: " + plainKey.equals(decryptedPlainKey));
		System.out.println("plainKey == decryptedPlainKey as raw bytes?: " + Arrays.equals(getBytes(plainKey), getBytes(decryptedPlainKey)));

		// Direct encryption/decryption up to 4 KB data
		String textToEncrypt = "Zory, a nice town in Poland";
		System.out.println("text to be encrypted: " + textToEncrypt);
		EncryptResult cipherText = kms
				.encrypt(new EncryptRequest().withKeyId(keyId).withPlaintext(ByteBuffer.wrap(textToEncrypt.getBytes(StandardCharsets.UTF_8))));
		String s = Base64.getEncoder().encodeToString(getBytes(cipherText.getCiphertextBlob()));

		ByteBuffer bb = ByteBuffer.wrap(Base64.getDecoder().decode(s));
		String decryptedText = new String(getBytes(kms.decrypt(new DecryptRequest().withCiphertextBlob(bb)).getPlaintext()), StandardCharsets.UTF_8);
		System.out.println("decrypted text: " + decryptedText);

	}

	private static byte[] getBytes(ByteBuffer byteBuffer) {
		ByteBuffer readOnly = byteBuffer.asReadOnlyBuffer();
		byte[] bytes = new byte[readOnly.remaining()];
		readOnly.get(bytes);
		return bytes;
	}

}
