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
<script src="https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.3.1.min.js"></script>
<script type="text/javascript" src="http://18.204.227.194/it5236/website/js/current_page.js"></script>
<div id="header">
		<div class="nav">
			<a id="index" href="index.php">Home</a>
			&nbsp;&nbsp;
			<?php if (!$loggedin) { ?>
				<a id="login" href="login.php">Login</a>
				&nbsp;&nbsp;
				<a id="register" href="register.php">Register</a>
				&nbsp;&nbsp;
			<?php } ?>
			<?php if ($loggedin) { ?>
				<a id="list" href="list.php">List</a>
				&nbsp;&nbsp;
				<a id="editprofile" href="editprofile.php">Profile</a>
				&nbsp;&nbsp;
				<?php if ($isadmin) { ?>
					<a id="admin" href="admin.php">Admin</a>
					&nbsp;&nbsp;
				<?php } ?>
				<a id="fileviewer" href="fileviewer.php?file=include/help.txt">Help</a>
				&nbsp;&nbsp;
				<a href="logout.php">Logout</a>
				&nbsp;&nbsp;

			<?php } ?>
		</div>
		<h1>MusiConvo</h1>
	</div>
	<div id="wrapper">
