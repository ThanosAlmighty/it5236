<?php
	require_once('include/classes.php');

	$app = new Application();
	$app->setup();

	$app->protectPage($errors, FALSE, TRUE);

	$errors = array();
	$otp = '';
	$sessionid = '';
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	$otp = $_POST['OTP'];
	if(!isset($_COOKIE['sessionid']) || empty($_COOKIE['sessionid'])){
		$errors[] = "You do not have a valid session";
	} else {
		$sessionid = $_COOKIE['sessionid'];
	}
	if(empty($otp)){
		$errors[] = "Please enter your One Time Password";
	}
	if(sizeof($errors) == 0){
		$result = $app->verify_otp($otp, $sessionid);
		// If the query did not run successfully, add an error message to the list
		if ($result == 0) {
			$errors[] = "Invalid session/OTP combination";
			$app->auditlog("OTP", $errors);
		} else {
			$app->auditlog("OTP success", "OTP valid. User logged in");
			header('Location: list.php');
			exit();
		}
	} else{
		$app->auditlog("OTP", $errors);
	}
}

?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>MusiConvo - MFA</title>
	<meta name="description" content="Jonathan Huling's personal website for IT 5236">
	<meta name="author" content="Jonathan Huling">
	<link rel="stylesheet" href="css/style.css">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<!--1. Display Errors if any exists
	2. Display Login form (sticky):  Username and Password -->

<body>
	<?php include 'include/header.php'; ?>

	<h2>One Time Password - MFA</h2>

	<?php include('include/messages.php'); ?>

	<div>
		<form method="post" action="otp.php">

			<input type="text" name="OTP" id="password" placeholder="One Time Password"/>
			<br/>

			<input type="submit" value="Login" name="login" />
		</form>
	</div>
	<a href="register.php">Need to create an account?</a>
	<br/>
	<?php include 'include/footer.php'; ?>
	<script src="js/site.js"></script>
</body>
</html>
