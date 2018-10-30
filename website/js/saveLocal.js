function doSubmit(e) {
	var saveLocal = document.getElementById("saveLocal").checked;
	if (saveLocal) {
		console.log("Saving username to local storage");
		var username = document.getElementById("username").value;
		localStorage.setItem("username",username);
	} else {
		localStorage.removeItem("username");
	}
}
function doPageLoad(e) {
	console.log("Reading username from local/session storage");
	var usernameLocal = localStorage.getItem("username");
	if (usernameLocal) {
		document.getElementById("saveLocal").checked = true;
		document.getElementById("username").value = usernameLocal;
	}
}

// Add event listeners for page load and form submit
window.addEventListener("load", doPageLoad, false);
document.getElementById("loginForm").addEventListener("submit", doSubmit, false);
