<?php
	require_once('include/classes.php');

	$app = new Application();
	$app->setup();

	$app->protectPage($errors, TRUE);

	$errors = array();
	$otp = '';
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	$otp = $_POST['OTP'];
	if(!isset($_COOKIE['sessionid']) || empty($_COOKIE['sessionid'])){
		$errors[] = "You do not have a valid session";
	}
	if(empty($otp)){
		$errors[] = "Please enter your One Time Password";
	}
	if(sizeof($errors) == 0){
		$dbh = $this->getConnection();

		$sql = "DELETE FROM OTP WHERE otp = :otp AND sessionid = :sessionid";

		$stmt = $dbh->prepare($sql);
		$stmt->bindParam(":otp", $otp);
		$stmt->bindParam(":sessionid", $sessionid);
		$result = $stmt->execute();

		// If the query did not run successfully, add an error message to the list
		if ($result === FALSE) {
			$errors[] = "Invalid session/OTP combination";
			$this->auditlog("OTP", $errors);
		} else {
			$this->auditlog("OTP success", "OTP valid. User logged in");
			header('Location: list.php');
			exit();
		}
	} else{
		$this->auditlog("OTP", $errors);
	}
	$dbh = NULL;
}

?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>jonathanhuling.me</title>
	<meta name="description" content="Jonathan Huling's personal website for IT 5236">
	<meta name="author" content="Jonathan Huling">
	<link rel="stylesheet" href="css/style.css">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<!--1. Display Errors if any exists
	2. Display Login form (sticky):  Username and Password -->

<body>
	<?php include 'include/header.php'; ?>

	<h2>Login</h2>

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
