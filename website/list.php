<?php

// Import the application classes
require_once('include/classes.php');

// Create an instance of the Application class
$app = new Application();
$app->setup();

// Declare an empty array of error messages
$errors = array();

// Check for logged in user since this page is protected
$app->protectPage($errors);

$name = "";

// Attempt to obtain the list of things
$things = $app->getThings($errors);

// Check for url flag indicating that there was a "no thing" error.
if (isset($_GET["error"]) && $_GET["error"] == "nothing") {
	$errors[] = "Topic not found.";
}

// Check for url flag indicating that a new thing was created.
if (isset($_GET["newthing"]) && $_GET["newthing"] == "success") {
	$message = "Topic successfully created.";
}

// If someone is attempting to create a new thing, the process the request
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	// Pull the title and thing text from the <form> POST
	$name = $_POST['name'];
	$attachment = $_FILES['attachment'];

	// Attempt to create the new thing and capture the result flag
	$result = $app->addThing($name, $attachment, $errors);

	// Check to see if the new thing attempt succeeded
	if ($result == TRUE) {

		// Redirect the user to the login page on success
	    header("Location: list.php?newthing=success");
		exit();

	}

}

?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>MusiConvo - Topic List</title>
	<meta name="description" content="Jonathan Huling's personal website for IT 5233">
	<meta name="author" content="Jonathan Huling">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<script src="https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.3.1.min.js"></script>
	<script type="text/javascript" src="http://localhost/it5236/website/js/current_page.js"></script>
	<link rel="stylesheet" href="css/style.css">
</head>

<!--1. Display Errors if any exists
	2. If no errors display things -->
<body>
	<?php include 'include/header.php'; ?>
	<h2>Topics</h2>

	<?php include('include/messages.php'); ?>
	<div class="search">
		<form action="list.php" method="post">
			<label for="search">Filter:</label>
			<input type="text" id="search" name="search"/>
			<input type="submit" value="Apply" />
		</form>
	</div>
	<ul class="things">
		<?php if (sizeof($things) == 0) { ?>
		<li>No topics found</li>
		<?php } ?>
		<?php foreach ($things as $thing) { ?>
		<li>
			<a href="thing.php?thingid=<?php echo $thing['thingid']; ?>"><?php echo $thing['thingname']; ?></a>
			<span class="author"><?php echo $thing['thingcreated']; ?></span>
		</li>
		<?php } ?>

	</ul>
	<div class="newthing">
		<form enctype="multipart/form-data" method="post" action="list.php">
			<input type="text" name="name" id="name" size="50" placeholder="Enter a topic name" value="<?php echo $name; ?>" />
			<br/>
			<label for="attachment">Add an image, PDF, etc.</label>
			<input id="attachment" name="attachment" type="file">
			<br/>
			<input type="submit" name="start" value="Create Topic" />
			<input type="submit" name="cancel" value="Cancel" />
		</form>
	</div>
	<?php include 'include/footer.php'; ?>
	<script src="js/site.js"></script>
</body>
</html>
