<%@page session="false"%>
<%@taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html lang="en">
<head>
<spring:url value="/resources/core/css/bootstrap.min.css"
	var="bootstrapCss" />
<link href="${bootstrapCss}" rel="stylesheet" />
<script src="https://code.jquery.com/jquery-3.2.1.min.js"></script>
<script
	src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>

</head>

<nav class="navbar navbar-inverse">
	<div class="container">
		<div class="navbar-header">
			<a class="navbar-brand" href="#">OIDC-Client</a>
		</div>
	</div>
</nav>
<body>
	<div class="container" style="min-height: 500px">
		<button id="start">Start</button>
		<button id="config" data-toggle="modal" class="pull-right">
			<!-- data-target="#configModal" -->
			Configuration <span class="glyphicon glyphicon-cog"></span>
		</button>


		<div class="modal fade" id="configModal" role="dialog">
			<div class="modal-dialog">

				<!-- Modal content-->
				<div class="modal-content">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal">&times;</button>
						<h4 class="modal-title">Open ID Connect Configuration</h4>
					</div>
					<div class="modal-body">
						<form class="form-horizontal" id="submit-form" method="post">
							<div class="form-group form-group-lg">
								<label class="col-sm-2 control-label">Authorization
									Endpoint:</label>
								<div class="col-sm-10">
									<input type="text" class="form-control"
										id="authorizationEndpoint">
								</div>
							</div>
							<div class="form-group form-group-lg">
								<label class="col-sm-2 control-label">Token Endpoint:</label>
								<div class="col-sm-10">
									<input type="text" class="form-control" id="tokenEndpoint">
								</div>
							</div>
							<div class="form-group form-group-lg">
								<label class="col-sm-2 control-label">Token Keys
									Endpoint:</label>
								<div class="col-sm-10">
									<input type="text" class="form-control" id="tokenKeysEndpoint">
								</div>
							</div>
							<div class="form-group form-group-lg">
								<label class="col-sm-2 control-label">Client ID:</label>
								<div class="col-sm-10">
									<input type=text class="form-control" id="clientId">
								</div>
							</div>
							<div class="form-group form-group-lg">
								<label class="col-sm-2 control-label">Client Secret:</label>
								<div class="col-sm-10">
									<input type="text" class="form-control" id="clientSecret">
								</div>
							</div>

							<div class="form-group form-group-lg">
								<label class="col-sm-2 control-label">Scope:</label>
								<div class="col-sm-10">
									<input type="text" class="form-control" id="scope">
								</div>
							</div>
							<div class="form-group form-group-lg">
								<label class="col-sm-2 control-label">OAuth Flow:</label>
								<div class="col-sm-10">
									<select id="authorization_Code_Flow">
										<option value="Authorization_Code_Flow">Authorization
											Code Flow</option>
									</select>
								</div>
							</div>
						</form>
					</div>
					<div class="modal-footer">
						<div class="form-group">
							<div class="col-sm-offset-2 col-sm-10">
								<button type="submit" id="btn-submit"
									class="btn btn-primary btn-md">Submit</button>

								<button type="button" class="btn btn-default btn-md"
									data-dismiss="modal">Close</button>
							</div>
						</div>
					</div>
				</div>

			</div>
		</div>

	</div>

	<script>
		var modal = document.getElementById('configModal');

		// Get the button that opens the modal
		var btn = document.getElementById("config");

		// Get the <span> element that closes the modal
		var span = document.getElementsByClassName("close")[0];

		// When the user clicks the button, open the modal 
		/* btn.onclick = function() {
			modal.style.display = "block";
		}

		// When the user clicks on <span> (x), close the modal
		span.onclick = function() {
			modal.style.display = "none";
		}

		// When the user clicks anywhere outside of the modal, close it
		window.onclick = function(event) {
			if (event.target == modal) {
				modal.style.display = "none";
			}
		} */

		$(function() {
			//console.log("ready");
			$('#config').click(function() {
				//console.log("config clicked.");
				$('#configModal').modal('toggle');
			});

			$("#submit-form").submit(function(event) {

				// Disble the search button
				enableSubmitButton(false);

				// Prevent the form from submitting via the browser.
				event.preventDefault();

				submitViaAjax();

			});

		});

		 $("#btn-submit").click(function() {

			 var dataString = {}
				dataString["authorizationTokenEndpoint"] = $(
						"#authorizationTokenEndpoint").val();
				dataString["tokenEndpoint"] = $("#tokenEndpoint").val();
				dataString["tokenKeysEndpoint"] = $("#tokenKeysEndpoint").val();
				dataString["clientId"] = $("#clientId").val();
				dataString["clientSecret"] = $("#clientsecret").val();
				dataString["scope"] = $("#scope").val();
				dataString["authorizationCodeFlow"] = $("#authorization_Code_Flow")
						.val();
				console.log(JSON.stringify(dataString));
				$.ajax({
					type : "POST",
				/* 	headers : {
						'Accept' : 'application/json',
						'Content-Type' : 'application/json'
					}, */
					contentType : "application/json",
					url : "${home}startOAuth",
					data : JSON.stringify(dataString),
					dataType : 'json',
					timeout : 100000,
					success : function(data) {
						console.log("SUCCESS: ", data);
						//display(data);
					},
					error : function(xhr,status,error) {
						console.log("ERROR:");
						console.log(xhr);
						console.log(status);
						console.log(error);
						//display(e);
					},
					done : function(e) {
						console.log("DONE");
						//enableSearchButton(true);
					}
				})/* .done(function() {
				    alert( "success" )) */; 

		});

/* 		function enableSubmitButton(flag) {
			$("#btn-submit").prop("disabled", flag);
		} */

	/* 	function display(data) {
			var json = "<h4>Ajax Response</h4><pre>"
					+ JSON.stringify(data, null, 4) + "</pre>";
			$('#feedback').html(json);
		} */
	</script>

</body>
</html>