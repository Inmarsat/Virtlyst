function checkPassword()
{
	passw = document.getElementById("password").value;
	
	var passwRegExp = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?!.*\s).{10,}$/;
	
	if(passw.match(passwRegExp)){
		//document.getElementById("form_id").submit();
		return true;
	}else{
		// alert("Password must contain at least one lowercase letter, one uppercase letter, one numeric digit, one special character, and at least 10 or more characters");
		eModal.alert("Password must contain at least one lowercase letter, one uppercase letter, one numeric digit, one special character, and at least 10 or more characters","FleetCompute Errors",);
		document.getElementById("password").focus();
		return false;
	}
}
