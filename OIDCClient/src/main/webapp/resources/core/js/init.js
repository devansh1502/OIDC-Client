$(document)
		.ready(
				function() {
					$("#submit")
							.click(
									function() {
										var ClientId = $("#clientId").val();
										var Clientsecret = $("#clientsecret")
												.val();
										var Scope = $("#scope").val();
										var Authorization_Code_Flow = $(
												"#Authorization_Code_Flow")
												.val();
										// Returns successful data submission
										// message when the entered information
										// is stored in database.
										// alert("HERE");
										var dataString = {
											clientId : ClientId,
											clientsecret : Clientsecret,
											scope : Scope,
											authorization_Code_Flow : Authorization_Code_Flow
										}
										console
												.log("dataString ="
														+ dataString);
										console.log("dataStringJson"
												+ JSON.stringify(dataString));
										// alert(JSON.stringify(dataString));
										if (ClientId == ''
												|| Clientsecret == ''
												|| Scope == ''
												|| Authorization_Code_Flow == '') {
											alert("Please Fill All Fields");
										} else {
											// AJAX Code To Submit Form.
											console.log('${home}');
											$
													.ajax({
														type : "POST",
														url : "${home}OIDCClient",
														contentType : 'application/json; charset=utf-8',
														dataType : 'json',
														data : JSON
																.stringify(dataString),
														cache : false,
														success : function(
																result) {
															alert(result);
														},
														error : function(jqXHR,
																textStatus,
																errorThrown) {
															console
																	.log(textStatus);
															console
																	.log(errorThrown);
														}
													});
										}
										return false;
									});
				});
