package com.soffid.iam.sync.agent.scim;

import java.util.List;

import javax.ws.rs.core.MediaType;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wink.client.ClientAuthenticationException;
import org.apache.wink.client.ClientConfig;
import org.apache.wink.client.ClientRequest;
import org.apache.wink.client.ClientResponse;
import org.apache.wink.client.Resource;
import org.apache.wink.client.RestClient;
import org.apache.wink.client.handlers.AbstractAuthSecurityHandler;
import org.apache.wink.client.handlers.BasicAuthSecurityHandler;
import org.apache.wink.client.handlers.ClientHandler;
import org.apache.wink.client.handlers.HandlerContext;
import org.apache.wink.common.http.HttpStatus;

public class TokenBasicHandler extends AbstractAuthSecurityHandler implements ClientHandler {

	Log logger = LogFactory.getLog(getClass());

	private String tokenURL;
	private String user;
	private String password;
	private String authToken;

	public TokenBasicHandler(String tokenURL, String user, String password) {
		this.tokenURL = tokenURL;
		this.user = user;
		this.password = password;
		this.authToken = null;
	}

	public ClientResponse handle(ClientRequest request, HandlerContext context) throws Exception {
		addHeader(request);
		logger.trace("Entering BasicAuthSecurityHandler.doChain()");
		try {
	        ClientResponse response = context.doChain(request);
	        if (response.getStatusCode() == HttpStatus. UNAUTHORIZED.getCode()) {
            	response.consumeContent();
            	logger.info("Receixed uauthorized. Renewing token");
				authToken = null;
				request.getHeaders().remove("Authorization");
				addHeader(request);
		        response = context.doChain(request);
	        }
			return  response;
		} catch (Exception th) {
			authToken = null;
			throw th;
		}
			
	}

	private void addHeader(ClientRequest request) {
		if (authToken == null)
			getAuthToken();
		if (authToken != null) {
			String auth = ("Bearer "+authToken);
			if (request.getHeaders().containsKey("Authorization")) {
				List<String> list = request.getHeaders().get("Authorization");
				list.add(auth);
				request.getHeaders().put("Authorization", list);
			} else {
				request.getHeaders().putSingle("Authorization", auth);
			}
		}
	}

	private void getAuthToken() {
		ClientConfig config = new ClientConfig();
		config.handlers(new BasicAuthSecurityHandler(this.user, this.password));

		logger.info("Requesting token");
		String basic = getEncodedString(this.user, this.password);
//		System.out.println("TokenHandler.getAuthToken() - user="+user);
//		System.out.println("TokenHandler.getAuthToken() - password="+password);
//		System.out.println("TokenHandler.getAuthToken() - basic="+basic);
//		System.out.println("TokenHandler.getAuthToken() - tokenURL="+tokenURL);
		RestClient client = new RestClient(config);
		Resource resource = client.resource(tokenURL);
		ClientResponse response = resource
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.header("Authorization", basic)
				.get();

		System.out.println("TokenHandler.getAuthToken() - response.getStatusCode()="+response.getStatusCode());
		System.out.println("TokenHandler.getAuthToken() - response.getMessage()="+response.getMessage());
		if (response.getStatusCode() == HttpStatus.OK.getCode()) {
			authToken = response.getEntity(String.class);
			System.out.println("TokenHandler.getAuthToken() - result="+authToken);
			if (authToken == null) {
				throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
			}
		} else {
			System.out.println("TokenHandler.getAuthToken() - response.getMessage()="+response.getMessage());
			throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
		}
		logger.info("Got token " + authToken);
	}
}
