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
<div id="header">
		<div class="nav">
			<a id="index.php" href="index.php">Home</a>
			&nbsp;&nbsp;
			<?php if (!$loggedin) { ?>
				<a id="login.php" href="login.php">Login</a>
				&nbsp;&nbsp;
				<a id="register.php" href="register.php">Register</a>
				&nbsp;&nbsp;
			<?php } ?>
			<?php if ($loggedin) { ?>
				<a id="list.php" href="list.php">List</a>
				&nbsp;&nbsp;
				<a id="editprofile.php" href="editprofile.php">Profile</a>
				&nbsp;&nbsp;
				<?php if ($isadmin) { ?>
					<a id="admin.php" href="admin.php">Admin</a>
					&nbsp;&nbsp;
				<?php } ?>
				<a id="fileviewer.php?file=include/help.txt" href="fileviewer.php?file=include/help.txt">Help</a>
				&nbsp;&nbsp;
				<a href="logout.php">Logout</a>
				&nbsp;&nbsp;

			<?php } ?>
		</div>
		<h1>MusiConvo</h1>
	</div>
