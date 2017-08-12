package com.gslab.oidc.Controller;

import java.util.List;

//import org.springframework.stereotype.Controller;
//import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonView;
//import com.gslab.oidc.model.AjaxResponseBody;
import com.gslab.oidc.jsonViews.Views;
import com.gslab.oidc.model.ClientRegistration;
import com.gslab.oidc.model.User;

@RestController
public class AjaxController {

	List<User> clients;

	// @ResponseBody, not necessary, since class is annotated with
	// @RestController
	// @RequestBody - Convert the json data into object (ClientRegistration)
	// mapped by field name.
	// @JsonView(Views.Public.class) - Optional, filters json data to display.
	@JsonView(Views.Public.class)
	@RequestMapping(value = "/OIDCClient1")
	public static String getSearchResultViaAjax(@RequestBody ClientRegistration clientRegistration) {
		System.out.println("HI am i being called");
		System.out.println("hello java");
		System.out.println("Client Id : " + clientRegistration.getClientId());
		System.out.println("Clientsecret : " + clientRegistration.getClientSecret());
		System.out.println("Scope : " + clientRegistration.getScope());
		System.out.println("Authorization_Code_Flow : " + clientRegistration.getAuthorizationCodeFlow());
/*
		AjaxResponseBody result = new AjaxResponseBody();

		if (isValidClientRegistration(clientRegistration)) {
			List<User> users = findByUserNameOrEmail(clientRegistration.getUsername(), clientRegistration.getEmail());

			if (users.size() > 0) {
				result.setCode("200");
				result.setMsg("");
				result.setResult(users);
			} else {
				result.setCode("204");
				result.setMsg("No user!");
			}

		} else {
			result.setCode("400");
			result.setMsg("Search criteria is empty!");
		}
*/
		//AjaxResponseBody will be converted into json format and send back to the request.
		return "result";
} 
/*
	private boolean isValidClientRegistration(ClientRegistration clientRegistration) {

		boolean valid = true;

		if (clientRegistration == null) {
			valid = false;
		}

		if ((StringUtils.isEmpty(clientRegistration.getClientId())) && (StringUtils.isEmpty(clientRegistration.getClientsecret()))) {
			valid = false;
		}

		return valid;*/

		// Init some clients for testing
		/*
		 * @PostConstruct private void iniDataForTesting() { clients = new
		 * ArrayList<User>();
		 * 
		 * User user1 = new User("mkyong", "pass123", "mkyong@yahoo.com",
		 * "012-1234567", "address 123"); User user2 = new User("yflow",
		 * "pass456", "yflow@yahoo.com", "016-7654321", "address 456"); User
		 * user3 = new User("laplap", "pass789", "mkyong@yahoo.com",
		 * "012-111111", "address 789"); clients.add(user1); clients.add(user2);
		 * clients.add(user3);
		 * 
		 * }
		 * 
		 * // Simulate the search function private List<User>
		 * findByUserNameOrEmail(String username, String email) {
		 * 
		 * List<User> result = new ArrayList<User>();
		 * 
		 * for (User user : clients) {
		 * 
		 * if ((!StringUtils.isEmpty(username)) &&
		 * (!StringUtils.isEmpty(email))) {
		 * 
		 * if (username.equals(user.getUsername()) &&
		 * email.equals(user.getEmail())) { result.add(user); continue; } else {
		 * continue; }
		 * 
		 * } if (!StringUtils.isEmpty(username)) { if
		 * (username.equals(user.getUsername())) { result.add(user); continue; }
		 * }
		 * 
		 * if (!StringUtils.isEmpty(email)) { if (email.equals(user.getEmail()))
		 * { result.add(user); continue; } }
		 * 
		 * }
		 
	}*/
}