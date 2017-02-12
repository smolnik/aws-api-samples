package cloud.developing.aws.samples;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.json.JSONObject;

import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.GetFederationTokenRequest;
import com.amazonaws.services.securitytoken.model.GetFederationTokenResult;

/**
 * @author asmolnik
 *
 */
public class FederatedUrlCreator {

	private static final String UTF_8 = StandardCharsets.UTF_8.name();

	public static void main(String[] args) throws Exception {
		AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient();
		String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":\"ec2:Describe*\"," + "\"Effect\":\"Allow\",\"Resource\":\"*\"}]}";
		GetFederationTokenRequest ftReq = new GetFederationTokenRequest().withDurationSeconds(3600).withName("federatedUser").withPolicy(policy);
		GetFederationTokenResult res = sts.getFederationToken(ftReq);
		// AssumeRoleResult res = sts.assumeRole(new AssumeRoleRequest().withDurationSeconds(3600).withRoleSessionName("ec2-describe-role")
		// .withRoleArn("arn:aws:iam::542175458111:role/ec2-describe-role"));

		Credentials fc = res.getCredentials();
		String signInURL = "https://signin.aws.amazon.com/federation";
		String sessionJson = String.format("{\"%1$s\":\"%2$s\",\"%3$s\":\"%4$s\",\"%5$s\":\"%6$s\"}", "sessionId", fc.getAccessKeyId(), "sessionKey",
				fc.getSecretAccessKey(), "sessionToken", fc.getSessionToken());
		String signinTokenUrl = signInURL + "?Action=getSigninToken" + "&SessionType=json&Session=" + URLEncoder.encode(sessionJson, UTF_8);
		// for assumeRole with SessionDuration=3600
		// String signinTokenUrl = signInURL + "?Action=getSigninToken" + "&SessionDuration=3600" + "&SessionType=json&Session="
		// + URLEncoder.encode(sessionJson, UTF_8);
		URLConnection con = new URL(signinTokenUrl).openConnection();
		try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));) {
			String returnContent = br.readLine();
			String signinToken = new JSONObject(returnContent).getString("SigninToken");
			String signinTokenParameter = "&SigninToken=" + URLEncoder.encode(signinToken, UTF_8);
			String issuerParameter = "&Issuer=" + URLEncoder.encode("mysupercompany.cloud", UTF_8);

			String destinationParameter = "&Destination=" + URLEncoder.encode("https://console.aws.amazon.com/ec2", UTF_8);
			String loginUrl = signInURL + "?Action=login" + signinTokenParameter + issuerParameter + destinationParameter;
			System.out.println(loginUrl);
		}

	}

}
