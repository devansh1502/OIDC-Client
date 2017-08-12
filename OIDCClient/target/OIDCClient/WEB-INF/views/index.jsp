<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
<head>
<script src="https://code.jquery.com/jquery-3.2.1.min.js"></script>
<style>
/* The Modal (background) */
.modal {
	display: none; /* Hidden by default */
	position: fixed; /* Stay in place */
	z-index: 1; /* Sit on top */
	padding-top: 100px; /* Location of the box */
	left: 0;
	top: 0;
	width: 100%; /* Full width */
	height: 100%; /* Full height */
	overflow: auto; /* Enable scroll if needed */
	background-color: rgb(0, 0, 0); /* Fallback color */
	background-color: rgba(0, 0, 0, 0.4); /* Black w/ opacity */
}

/* Modal Content */
.modal-content {
	background-color: #fefefe;
	margin: auto;
	padding: 20px;
	border: 1px solid #888;
	width: 80%;
}

/* The Close Button */
.close {
	color: #aaaaaa;
	float: right;
	font-size: 28px;
	font-weight: bold;
}

.close:hover, .close:focus {
	color: #000;
	text-decoration: none;
	cursor: pointer;
}
</style>
</head>
<body>

	<h2>OIDC Client</h2>

	<!-- Trigger/Open The Modal -->
	<button id="start">start</button>
	<button id="config">config</button>
	<!-- The Modal -->
	<div id="myModal" class="modal">

		<!-- Modal content -->
		<div class="modal-content">
			<span class="close">&times;</span>
			<form> <%-- action="${pageContext.request.contextPath}/OIDCClient" 
				method="post">--%>
				Authorization Token Endpoint:<br> <input type ="text" id ="authorizationTokenEndpoint"><br>
				Token Endpoint:<br> <input type ="text" id ="tokenEndpoint"><br>
				Token Keys Endpoint:<br> <input type ="text" id ="tokenKeysEndpoint"><br>
				Client ID:<br> <input type="text" id="clientId"><br>
				Client Secret:<br> <input type="text" id="clientsecret"><br>
				Scope:<br> <input type="text" id="scope"><br> 
				Code Flow:<br> <select id="Authorization_Code_Flow">
					<option value="Authorization_Code_Flow">Authorization Code
						Flow</option>
				</select><br> <input id="submit" type="submit" value="Submit">
			</form>
		</div>

	</div>

<script>

	var modal = document.getElementById('myModal');
	
	// Get the button that opens the modal
	var btn = document.getElementById("config");
	
	// Get the <span> element that closes the modal
	var span = document.getElementsByClassName("close")[0];

	// When the user clicks the button, open the modal 
	btn.onclick = function() {
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
	}

	jQuery(document).ready(function($) {

		$("#submit-form").submit(function(event) {

			// Disble the search button
			enableSubmitButton(false);

			// Prevent the form from submitting via the browser.
			event.preventDefault();

			submitViaAjax();

		});

	});

	function submitViaAjax() {

		var dataString = {}
		dataString["authorizationTokenEndpoint"]=$("#authorizationTokenEndpoint").val();
		dataString["tokenEndpoint"]=$("#tokenEndpoint").val();
		dataString["tokenKeysEndpoint"]=$("#tokenKeysEndpoint").val();
		dataString["clientId"] = $("#clientId").val();
		dataString["clientSecret"] = $("#clientsecret").val();
		dataString["scope"] = $("#scope").val();
		dataString["authorizationCodeFlow"] = $("#authorization_Code_Flow").val();
		console.log(JSON.stringify(dataString));
		$.ajax({
			type : "POST",
			 headers: { 
			        'Accept': 'application/json',
			        'Content-Type': 'application/json' 
			    },
			contentType : "application/json",
			url : "${home}startOAuth",
			data : JSON.stringify(dataString),
			dataType : 'json',
			timeout : 100000,
			success : function(data) {
				console.log("SUCCESS: ", data);
				display(data);
			},
			error : function(xhr,status,error) {
				console.log("jqXHR: ", xhr);
				display(e);
			},
			done : function(e) {
				console.log("DONE");
				enableSearchButton(true);
			}
		});

	}

	function enableSubmitButton(flag) {
		$("#btn-submit").prop("disabled", flag);
	}

	function display(data) {
		var json = "<h4>Ajax Response</h4><pre>"
				+ JSON.stringify(data, null, 4) + "</pre>";
		$('#feedback').html(json);
	}
</script>

	<%-- <script src="${pageContext.request.contextPath}/resources/core/js/jquery-3.2.1.min.js" type="text/javascript"></script>
	<script src="<c:url value="/resources/core/js/init.js" />" type="text/javascript"></script> --%>
</body>
</html>
