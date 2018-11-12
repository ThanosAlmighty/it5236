<?php
// Import the application classes
require_once('include/classes.php');

// Declare an empty array of error messages
$errors = array();

// Create an instance of the Application class
$app = new Application();
$app->setup();
$registrations = $app->getUserRegistrations($userid, $errors);
    foreach($registrations as $code){
      ?>
        <p>
          <?php echo $code; ?>
        </p>
      <?php
    }
?>
