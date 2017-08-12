package com.gslab.oidc.client;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
//import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.annotation.JsonView;
import com.gslab.oidc.jsonViews.Views;
import com.gslab.oidc.model.ClientRegistration;

@Controller
public class HomeController {
	private static final String ACCESS_TOKEN = "ACCESS_TOKEN";
	private static final String INSTANCE_URL = "INSTANCE_URL";
    //use properties file..(for client id and secret and everything else 
	
	// clientId is 'Consumer Key' in the Remote Access UI
	private String clientId = "3MVG9d8..z.hDcPLns0FEP7vMhKsiVdeOtmS_MlAA8xp3n7p.LvSmSG8Kz56bCFwWsv0sGlCfkePHXs8BqvC5";
	// clientSecret is 'Consumer Secret' in the Remote Access UI
	private String clientSecret = "3317252097875906329";
	// This must be identical to 'Callback URL' in the Remote Access UI
	private String redirectUri = "https://localhost:8443/OIDCClient/startOAuth/_callback";
	private String environment = "https://login.salesforce.com";
	private String authUrl = null;
	private String tokenUrl = null;
	private String userIdToken= null;
	String sessionStr="";

	@RequestMapping(value = "/")
	public String home() {

		return "Welcome2";
	}
	/*public String authenticate(HttpServletRequest request, HttpServletResponse response)
	throws ServletException, IOException {*/
	//@JsonView(Views.Public.class)
	@RequestMapping(value = "/startOAuth", method=RequestMethod.POST)
	public @ResponseBody String authenticate(@RequestBody ClientRegistration clientRegistration, HttpSession session) throws ServletException, IOException {
		/*System.out.println("HI am i being called");
		System.out.println("hello java");
		*/
		System.out.println("Authorization Token Endpoint :" + clientRegistration.getAuthorizationTokenEndpoint());
		System.out.println("Token Endpoint :" + clientRegistration.getTokenEndpoint());
		System.out.println("Token Keys Endpoint :" + clientRegistration.getTokenKeysEndpoint());
		System.out.println("Client Id : " + clientRegistration.getClientId());
		System.out.println("Client secret : " + clientRegistration.getClientSecret());
		System.out.println("Scope : " + clientRegistration.getScope());
		System.out.println("Authorization_Code_Flow : " + clientRegistration.getAuthorizationCodeFlow());
		
		session.setAttribute(sessionStr, clientRegistration);
		ClientRegistration cR = (ClientRegistration) session.getAttribute(sessionStr);
		System.out.println(cR.getAuthorizationTokenEndpoint());
		System.out.println(cR.getTokenEndpoint());
		System.out.println(cR.getTokenKeysEndpoint());
		System.out.println(cR.getClientId());
		System.out.println(cR.getClientSecret());
		System.out.println(cR.getScope());
		System.out.println(cR.getAuthorizationCodeFlow());

		//System.out.println("clientId" + request.getParameter("dataString"));
		//System.out.println("client = "+clientRegistration.getClientId());
		
	/*	
		String accessToken = (String) request.getSession().getAttribute(ACCESS_TOKEN);
		if (accessToken == null) {*/

			try {
				authUrl = environment + "/services/oauth2/authorize?response_type=code&scope=openid&client_id=" + cR.getClientId()
						+ "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				throw new ServletException(e);
			}

			//return "redirect:" + authUrl;
			return "Success";
		/*} else {
			return "redirect:/startOAuth/_callback";
		}*/
	}

	@RequestMapping(value = "/startOAuth/_callback")
	@ResponseBody
	public String authenticateCallback(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		String accessToken = (String) request.getSession().getAttribute(ACCESS_TOKEN);

		if (accessToken == null) {
			String instanceUrl = null;

			tokenUrl = environment + "/services/oauth2/token";

			String code = request.getParameter("code");

			HttpClient httpclient = new HttpClient();

			PostMethod post = new PostMethod(tokenUrl);
			post.addParameter("code", code);
			post.addParameter("grant_type", "authorization_code");
			post.addParameter("client_id", clientId);
			post.addParameter("client_secret", clientSecret);
			post.addParameter("redirect_uri", redirectUri);

			try {
				httpclient.executeMethod(post);

				try {
					JSONObject authResponse = new JSONObject(
							new JSONTokener(new InputStreamReader(post.getResponseBodyAsStream())));
					System.out.println("Auth response: " + authResponse.toString(2));

					accessToken = authResponse.getString("access_token");
					instanceUrl = authResponse.getString("instance_url");
					userIdToken = authResponse.getString("id_token");
					
					System.out.println("Acess Token Acquired" + accessToken);
					System.out.println("ID Token =" + userIdToken);
					
					String[] idTokenFields = userIdToken.split("\\.");
					byte[] idTokenHeaderBytes = idTokenFields[1].getBytes(); 
					byte[] idTokenPayloadBytes = idTokenFields[2].getBytes();
					// Decoding id_token.
					System.out.println("ID Token header = " + new String(Base64.decodeBase64(idTokenHeaderBytes)));
					System.out.println("ID Token Payload = " + new String(Base64.decodeBase64(idTokenPayloadBytes)));
					//System.out.println("ID Token Payload = " + new String(Base64.decodeBase64(userIdToken.split("\\.")[1])));

		} catch (JSONException e) {
					e.printStackTrace();
					throw new ServletException(e);
				}
			} finally {
				post.releaseConnection();
			}
			// Set a session attribute so that other servlets can get the access
			// token
			request.getSession().setAttribute(ACCESS_TOKEN, accessToken);

			// We also get the instance URL from the OAuth response, so set it
			// in the session too
			request.getSession().setAttribute(INSTANCE_URL, instanceUrl);
		}

		return "Logged in! <a href=\"/logout\">Log out</a> | " + "<a href=\"/accounts\">Get accounts</a> | "
				+ "Got access token: " + accessToken;
	}

	/*@RequestMapping(value = "/logout")
	@ResponseBody
	public String logout(HttpServletRequest request) {
		HttpSession session = request.getSession();
		session.removeAttribute(ACCESS_TOKEN);
		session.removeAttribute(INSTANCE_URL);
		return "logged out! <a href=\"/auth\">login</a>";
	}*/

	/*@RequestMapping(value = "/accounts")
	@ResponseBody
	public String accounts(HttpServletRequest request) throws ServletException {
		HttpSession session = request.getSession();
		String accessToken = (String) session.getAttribute(ACCESS_TOKEN);
		String instanceUrl = (String) session.getAttribute(INSTANCE_URL);
		if (accessToken == null) {
			return "<a href=\"/logout\">Log out</a> | Error - no access token";
		}
		StringBuffer writer = new StringBuffer();
		writer.append("We have an access token: " + accessToken + "<br />" + "Using instance " + instanceUrl
				+ "<br /><br />");
		HttpClient httpclient = new HttpClient();
		GetMethod get = new GetMethod(instanceUrl + "/services/data/v20.0/query");
		// set the token in the header
		get.setRequestHeader("Authorization", "OAuth " + accessToken);
		// set the SOQL as a query param
		NameValuePair[] params = new NameValuePair[1];
		params[0] = new NameValuePair("q", "SELECT Id, Name from Account LIMIT 100");
		get.setQueryString(params);
		try {
			httpclient.executeMethod(get);
			if (get.getStatusCode() == HttpStatus.SC_OK) {
				// Now lets use the standard java json classes to work with the
				// results
				try {
					JSONObject response = new JSONObject(
							new JSONTokener(new InputStreamReader(get.getResponseBodyAsStream())));
					System.out.println("Query response: " + response.toString(2));
					writer.append(response.getString("totalSize") + " record(s) returned<br /><br />");
					JSONArray results = response.getJSONArray("records");
					for (int i = 0; i < results.length(); i++) {
						writer.append(results.getJSONObject(i).getString("Id") + ", "
								+ results.getJSONObject(i).getString("Name") + "<br />");
					}
					writer.append("<br />");
				} catch (JSONException e) {
					e.printStackTrace();
					throw new ServletException(e);
				} catch (IOException e) {
					e.printStackTrace();
					throw new ServletException(e);
				}
			}
		} catch (HttpException e) {
			e.printStackTrace();
			throw new ServletException(e);
		} catch (IOException e) {
			e.printStackTrace();
			throw new ServletException(e);
		} finally {
			get.releaseConnection();
		}
		return writer.toString();
	}
*/
}