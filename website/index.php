<?php

// Import the application classes
require_once('include/classes.php');

// Create an instance of the Application class
$app = new Application();
$app->setup();

// Declare an empty array of error messages
$errors = array();

?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>MusiConvo - Home</title>
	<meta name="description" content="Jonathan Huling's personal website for IT 5236">
	<meta name="author" content="Jonathan Huling">
	<link rel="stylesheet" href="css/style.css">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
	<?php include 'include/header.php'; ?>
	<h2>Home</h2>
	<p>
		This is a "list-oriented" web application for use by any student interested in talking about music. Currently only accepting registrations from users with Georgia Southern University email addresses.
		Students not registered for the course may <a href="register.php">create an account</a>. Otherwise proceed directly to the
		<a href="login.php">login page</a>.
		<br>
		Happy posting!
	</p>
	<?php include 'include/footer.php'; ?>
	<script src="js/site.js"></script>
</body>
</html>
