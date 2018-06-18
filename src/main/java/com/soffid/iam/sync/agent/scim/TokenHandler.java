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
import org.apache.wink.client.handlers.ClientHandler;
import org.apache.wink.client.handlers.HandlerContext;
import org.apache.wink.common.http.HttpStatus;
import org.json.JSONException;
import org.json.JSONObject;

public class TokenHandler extends AbstractAuthSecurityHandler implements ClientHandler {

	Log logger = LogFactory.getLog(getClass());

	private String authURL;
	private String password;
	private String user;
	private String authToken;
	
	public TokenHandler ( String authURL, String user, String password) {
		this.authURL = authURL;
		this.user = user;
		this.password = password;
		this.authToken = null;
	}
	
	private void getAuthToken () throws JSONException {
		System.out.println("TokenHandler.getAuthToken()");
		ClientConfig config = new ClientConfig();
		RestClient client = new RestClient(config);
		Resource rsc = client.resource(authURL);

		String form = "username="+Utils.URLEncode(user)+"&password="+Utils.URLEncode(password);
		ClientResponse response = rsc
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.accept(MediaType.APPLICATION_JSON)
				.post(form);
		System.out.println("TokenHandler.getAuthToken() - response="+response);
		System.out.println("TokenHandler.getAuthToken() - response.getStatusCode()="+response.getStatusCode());
		if (response.getStatusCode() == HttpStatus.OK.getCode())
		{
			JSONObject result = response.getEntity(JSONObject.class);
			System.out.println("TokenHandler.getAuthToken() - result="+result);
			authToken = result.getString("token");
			System.out.println("TokenHandler.getAuthToken() - authToken="+authToken);
			if (authToken == null)
				throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
		} else {
			System.out.println("TokenHandler.getAuthToken() - response.getMessage()="+response.getMessage());
			throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
		}
	}
	
	public ClientResponse handle(ClientRequest request, HandlerContext context)
			throws Exception {
		if (authToken == null)
			getAuthToken();
		if (authToken != null)
		{
			String auth = ("Token "+authToken);
			if (request.getHeaders().containsKey("Authorization"))
			{
				List<String> list = request.getHeaders().get("Authorization");
				list.add(auth);
				request.getHeaders().put("Authorization", list);
			}
			else
				request.getHeaders().putSingle("Authorization", "Token "+authToken);
		}
		logger.trace("Entering BasicAuthSecurityHandler.doChain()"); //$NON-NLS-1$
		return  context.doChain(request);
	}
}
