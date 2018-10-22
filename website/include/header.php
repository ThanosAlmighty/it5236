<?php

	// Assume the user is not logged in and not an admin
	$isadmin = FALSE;
	$loggedin = FALSE;

	// If we have a session ID cookie, we might have a session
	if (isset($_COOKIE['sessionid'])) {

		$user = $app->getSessionUser($errors);
		$loggedinuserid = $user["userid"];

		// Check to see if the user really is logged in and really is an admin
		if ($loggedinuserid != NULL) {
			$loggedin = TRUE;
			$isadmin = $app->isAdmin($errors, $loggedinuserid);
		}

	} else {

		$loggedinuserid = NULL;

	}


?>
	<div class="nav">
		<a href="index.php">Home</a>
		&nbsp;&nbsp;
		<?php if (!$loggedin) { ?>
			<a href="login.php">Login</a>
			&nbsp;&nbsp;
			<a href="register.php">Register</a>
			&nbsp;&nbsp;
		<?php } ?>
		<?php if ($loggedin) { ?>
			<a href="list.php">List</a>
			&nbsp;&nbsp;
			<a href="editprofile.php">Profile</a>
			&nbsp;&nbsp;
			<?php if ($isadmin) { ?>
				<a href="admin.php">Admin</a>
				&nbsp;&nbsp;
			<?php } ?>
			<a href="fileviewer.php?file=include/help.txt">Help</a>
			&nbsp;&nbsp;
			<a href="logout.php">Logout</a>
			&nbsp;&nbsp;

		<?php } ?>
	</div>
	<h1>MusiConvo (Than's Music Forum)</h1>
