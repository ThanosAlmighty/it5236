<?php

if (file_exists(getcwd() . "/include/credentials.php")) {
    require('credentials.php');
} else {
    echo "Application has not been configured. Copy and edit the credentials-sample.php file to credentials.php.";
    exit();
}

class Application {

    public $debugMessages = [];

    public function setup() {

        // Check to see if the client has a cookie called "debug" with a value of "true"
        // If it does, turn on error reporting
        if ($_COOKIE['debug'] == "true") {
            ini_set('display_errors', 1);
            ini_set('display_startup_errors', 1);
            error_reporting(E_ALL);
        }
    }

    // Writes a message to the debug message array for printing in the footer.
    public function debug($message) {
        $this->debugMessages[] = $message;
    }

    // Creates a database connection
    protected function getConnection() {

        // Import the database credentials
        $credentials = new Credentials();

        // Create the connection
        try {
            $dbh = new PDO("mysql:host=$credentials->servername;dbname=$credentials->serverdb", $credentials->serverusername, $credentials->serverpassword);
        } catch (PDOException $e) {
            print "Error connecting to the database.";
            die();
        }

        // Return the newly created connection
        return $dbh;
    }

    public function auditlog($context, $message, $priority = 0, $userid = NULL){

        // Declare an errors array
        $errors = [];

        // Connect to the database
        $dbh = $this->getConnection();

        // If a user is logged in, get their userid
        if ($userid == NULL) {

            $user = $this->getSessionUser($errors, TRUE);
            if ($user != NULL) {
                $userid = $user["userid"];
            }

        }

        $ipaddress = $_SERVER["REMOTE_ADDR"];
        var_dump($message);
        if (is_array($message)){
            $message = implode( ",", $message);
        }

        // Construct a SQL statement to perform the insert operation
        $sql = "INSERT INTO auditlog (context, message, logdate, ipaddress, userid) " .
            "VALUES (:context, :message, NOW(), :ipaddress, :userid)";

        // Run the SQL select and capture the result code
        $stmt = $dbh->prepare($sql);
        $stmt->bindParam(":context", $context);
        $stmt->bindParam(":message", $message);
        $stmt->bindParam(":ipaddress", $ipaddress);
        $stmt->bindParam(":userid", $userid);
        $stmt->execute();
        $dbh = NULL;

    }

    protected function validateUsername($username, &$errors) {
        if (empty($username)) {
            $errors[] = "Missing username";
        } else if (strlen(trim($username)) < 3) {
            $errors[] = "Username must be at least 3 characters";
        } else if (strpos($username, "@")) {
            $errors[] = "Username may not contain an '@' sign";
        }
    }

    protected function validatePassword($password, &$errors) {
        if (empty($password)) {
            $errors[] = "Missing password";
        } else if (strlen(trim($password)) < 8) {
            $errors[] = "Password must be at least 8 characters";
        }
    }

    protected function validateEmail($email, &$errors) {
        if (empty($email)) {
            $errors[] = "Missing email";
        } else if (substr(strtolower(trim($email)), -20) != "@georgiasouthern.edu"
            && substr(strtolower(trim($email)), -13) != "@thackston.me") {
                // Verify it's a Georgia Southern email address
                $errors[] = "Not a Georgia Southern email address";
            }
    }

    // Registers a new user
    public function register($username, $password, $email, $registrationcode, &$errors) {

      $this->auditlog("register", "attempt: $username, $email, $registrationcode");

      // Validate the user input
      $this->validateUsername($username, $errors);
      $this->validatePassword($password, $errors);
      $this->validateEmail($email, $errors);
      if (empty($registrationcode)) {
          $errors[] = "Missing registration code";
      }

      // Only try to insert the data into the database if there are no validation errors
      if (sizeof($errors) == 0) {

      // Hash the user's password
      $passwordhash = password_hash($password, PASSWORD_DEFAULT);

      // Create a new user ID
      $userid = bin2hex(random_bytes(16));
 			$url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/register_user";
			$data = array(
				'userid'=>$userid,
				'username'=>$username,
				'passwordHash'=>$passwordhash,
				'email'=>$email,
				'registrationcode'=>$registrationcode
			);
			$data_json = json_encode($data);
 			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);
 			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {
 				if($httpCode == 400) {

					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode($response)->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}
 				} else if($httpCode == 500) {
 					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}
 				} else if($httpCode == 200) {
 					$this->sendValidationEmail($userid, $email, $errors);
 				}
 			}

         } else {
            $this->auditlog("register validation error", $errors);
        }

        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }

    // Send an email to validate the address
    protected function sendValidationEmail($userid, $email, &$errors) {

        $this->auditlog("sendValidationEmail", "Sending message to $email");

        $validationid = bin2hex(random_bytes(16));

        // Connect to the API
        $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/sendValidationEmail";
  			$data = array(
  				'userid'=>$userid,
  				'email'=>$email,
  				'emailvalidationid'=>$validationid
  			);
  			$data_json = json_encode($data);
   			$ch = curl_init();
  			curl_setopt($ch, CURLOPT_URL, $url);
  			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
  			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
  			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
  			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  			$response  = curl_exec($ch);
  			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
   			if ($response === FALSE) {
  				$errors[] = "An unexpected failure occurred contacting the web service.";
  			} else {
   				if($httpCode == 400) {
  					// JSON was double-encoded, so it needs to be double decoded
  					$errorsList = json_decode(json_decode($response))->errors;
  					foreach ($errorsList as $err) {
  						$errors[] = $err;
  					}
  					if (sizeof($errors) == 0) {
  						$errors[] = "Bad input";
  					}
   				} else if($httpCode == 500) {
   					$errorsList = json_decode(json_decode($response))->errors;
  					foreach ($errorsList as $err) {
  						$errors[] = $err;
  					}
  					if (sizeof($errors) == 0) {
  						$errors[] = "Server error";
  					}
   				} else if($httpCode == 200) {
            if ($response === 0) {
                $errors[] = "An unexpected error occurred sending the validation email";
                $this->debug($stmt->errorInfo());
                $this->auditlog("register error", "User could not be created");
            } else {

                $this->auditlog("sendValidationEmail", "Sending message to $email");

                // Send reset email
                $pageLink = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
                $pageLink = str_replace("register.php", "login.php", $pageLink);
                $to      = $email;
                $subject = 'Confirm your email address';
                $message = "A request has been made to create an account at https://jonathanhuling.me for this email address. ".
                    "If you did not make this request, please ignore this message. No other action is necessary. ".
                    "To confirm this address, please click the following link: $pageLink?id=$validationid";
                $headers = 'From: no-reply@jonathanhuling.me' . "\r\n";

                mail($to, $subject, $message, $headers);

                $this->auditlog("sendValidationEmail", "Message sent to $email");
            }
   				}
   			}
    }

    // Send an email to validate the address
    public function processEmailValidation($validationid, &$errors) {

        $success = FALSE;
        $this->auditlog("processEmailValidation", "Received: $validationid");
        // Connect to the API
        $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/processEmailValidation";
  			$data = array(
  				'emailvalidationid'=>$validationid
  			);
  			$data_json = json_encode($data);
   			$ch = curl_init();
  			curl_setopt($ch, CURLOPT_URL, $url);
  			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
  			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
  			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
  			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  			$response  = curl_exec($ch);
  			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
   			if ($response === FALSE) {
  				$errors[] = "An unexpected failure occurred contacting the web service.";
  			} else {
   				if($httpCode == 400) {
  					// JSON was double-encoded, so it needs to be double decoded
  					$errorsList = json_decode(json_decode($response))->errors;
  					foreach ($errorsList as $err) {
  						$errors[] = $err;
  					}
  					if (sizeof($errors) == 0) {
  						$errors[] = "Bad input";
  					}
   				} else if($httpCode == 500) {
   					$errorsList = json_decode(json_decode($response))->errors;
  					foreach ($errorsList as $err) {
  						$errors[] = $err;
  					}
  					if (sizeof($errors) == 0) {
  						$errors[] = "Server error";
  					}
   				} else if($httpCode == 200) {
            if ($response == 0) {
                $errors[] = "An unexpected error occurred processing your email validation";
                $this->auditlog("register error", "Update query affected 0 rows");
            } else if($response == 1) {
              $success = TRUE;
            } else {
              $errors[] = $response;
              $this->debug("Unexpected result");
              $this->auditlog("processEmailValidation", "Invalid request: $validationid");
            }
          }
        }
        return $success;
    }

    // Creates a new session in the database for the specified user
    public function newSession($userid, &$errors, $registrationcode = NULL) {

        // Check for a valid userid
        if (empty($userid)) {
            $errors[] = "Missing userid";
            $this->auditlog("session", "missing userid");
        }

        // Only try to query the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {

            if ($registrationcode == NULL) {
                $regs = $this->getUserRegistrations($userid, $errors);
                $reg = $regs[0];
                $this->auditlog("session", "logging in user with first reg code $reg");
                $registrationcode = $regs[0];
            }
            $return_value = NULL;
            // Create a new session ID
            $sessionid = bin2hex(random_bytes(25));

            // Connect to the API
            $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/createUserSession";
      			$data = array(
      				'userid'=>$userid,
      				'sessionid'=>$sessionid,
      				'registrationcode'=>$registrationcode
      			);
      			$data_json = json_encode($data);
       			$ch = curl_init();
      			curl_setopt($ch, CURLOPT_URL, $url);
      			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
      			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
      			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
      			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      			$response  = curl_exec($ch);
      			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
       			if ($response === FALSE) {
      				$errors[] = "An unexpected failure occurred contacting the web service.";
      			} else {
       				if($httpCode == 400) {
      					// JSON was double-encoded, so it needs to be double decoded
      					$errorsList = json_decode($response)->errors;
      					foreach ($errorsList as $err) {
      						$errors[] = $err;
      					}
      					if (sizeof($errors) == 0) {
      						$errors[] = "Bad input";
      					}
       				} else if($httpCode == 500) {
       					$errorsList = json_decode($response)->errors;
      					foreach ($errorsList as $err) {
      						$errors[] = $err;
      					}
      					if (sizeof($errors) == 0) {
      						$errors[] = "Server error";
      					}
       				} else if($httpCode == 200) {
                // If the query did not run successfully, add an error message to the list
                if ($response == 0) {
                    $errors[] = "An unexpected error occurred creating a session";
                    $this->debug("Server failed to insert session");
                    $this->auditlog("new session error", "Server failed to insert session");
                } else if($response == 1) {
                    // Store the session ID as a cookie in the browser
                    setcookie('sessionid', $sessionid, time()+60*60*24*30);
                    $this->auditlog("session", "new session id: $sessionid for user = $userid");
                    // Return the session ID
                    $return_value = $sessionid;
                }
       				}
       			}
            return $return_value;
        }

    }

    public function getUserRegistrations($userid, &$errors) {

        // Assume an empty list of regs
        $regs = array();

		$url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/getUserRegistrations?userid=" . $userid;
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$response  = curl_exec($ch);
		$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
		if ($response === FALSE) {
			$errors[] = "An unexpected failure occurred contacting the web service.";
		} else {
			if($httpCode == 400) {

				// JSON was double-encoded, so it needs to be double decoded
				$errorsList = json_decode(json_decode($response))->errors;
				foreach ($errorsList as $err) {
					$errors[] = $err;
				}
				if (sizeof($errors) == 0) {
					$errors[] = "Bad input";
				}
			} else if($httpCode == 500) {
				$errorsList = json_decode(json_decode($response))->errors;
				foreach ($errorsList as $err) {
					$errors[] = $err;
				}
				if (sizeof($errors) == 0) {
					$errors[] = "Server error";
				}
			} else if($httpCode == 200) {
	          $this->auditlog("getUserRegistrations", "web service response => " . $response);
				    $regs = json_decode($response)->userregistrations;
		        $this->auditlog("getUserRegistrations", "success");
			}
		}
        // Return the list of users
        return $regs;
    }

    // Updates a single user in the database and will return the $errors array listing any errors encountered
    public function updateUserPassword($userid, $password, &$errors) {

        // Validate the user input
        if (empty($userid)) {
            $errors[] = "Missing userid";
        }
        $this->validatePassword($password, $errors);

        if(sizeof($errors) == 0) {
            $passwordhash = password_hash($password, PASSWORD_DEFAULT);
            // Connect to the API
            $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/updateUserPassword";
      			$data = array(
      				'passwordhash'=>$passwordhash,
              'userid'=>$userid
      			);
      			$data_json = json_encode($data);
       			$ch = curl_init();
      			curl_setopt($ch, CURLOPT_URL, $url);
      			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
      			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
      			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
      			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      			$response  = curl_exec($ch);
      			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
       			if ($response === FALSE) {
      				$errors[] = "An unexpected failure occurred contacting the web service.";
      			} else {
       				if($httpCode == 400) {
      					// JSON was double-encoded, so it needs to be double decoded
      					$errorsList = json_decode(json_decode($response))->errors;
      					foreach ($errorsList as $err) {
      						$errors[] = $err;
      					}
      					if (sizeof($errors) == 0) {
      						$errors[] = "Bad input";
      					}
       				} else if($httpCode == 500) {
       					$errorsList = json_decode(json_decode($response))->errors;
      					foreach ($errorsList as $err) {
      						$errors[] = $err;
      					}
      					if (sizeof($errors) == 0) {
      						$errors[] = "Server error";
      					}
       				} else if($httpCode == 200) {
                if ($response == 0) {
                  $errors[] = "An unexpected error occurred supdating the password.";
                  $this->debug('Database could not find userid');
                  $this->auditlog("updateUserPassword error when finding userid", "userid: $userid");
                } else if($response == 1) {
                  $this->auditlog("updateUserPassword", "success");
                } else {
                  $errors[] = $response;
                  $this->debug("Unexpected API response");
                  $this->auditlog("updateUserPassword", "Invalid request: $userid");
                }
              }
            }

        } else {

            $this->auditlog("updateUserPassword validation error", $errors);

        }

        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }

    // Removes the specified password reset entry in the database, as well as any expired ones
    // Does not retrun errors, as the user should not be informed of these problems
    protected function clearPasswordResetRecords($passwordresetid) {

      $data_json = json_encode(array("passwordresetid"=>$passwordresetid));
      // Connect to the API
      $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/clearPasswordResetRecords";
      $ch = curl_init();
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
      curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
      curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      $response  = curl_exec($ch);
      $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);
      if ($response === FALSE) {
        $errors[] = "An unexpected failure occurred contacting the web service.";
      } else {
        if($httpCode == 400) {
          // JSON was double-encoded, so it needs to be double decoded
          $errorsList = json_decode(json_decode($response))->errors;
          $this->auditlog("clearPasswordResetRecords: Bad Request", $errorsList);
        } else if($httpCode == 500) {
          $errorsList = json_decode(json_decode($response))->errors;
          $this->auditlog("clearPasswordResetRecords: Internal Server Error", $errorsList);
        } else if($httpCode == 200) {
          if ($response == 0) {
            $this->auditlog("clearPasswordResetRecords: ", "reset id not found");
          } else {
            $this->auditlog("clearPasswordResetRecords: ", "Success!");
            $success = TRUE;
          }

        }

    }
  }

    // Retrieves an existing session from the database for the specified user
    public function getSessionUser(&$errors, $suppressLog=FALSE) {

        // Get the session id cookie from the browser
        $sessionid = NULL;
        $user_array = NULL;

        // Check for a valid session ID
        if (isset($_COOKIE['sessionid'])) {

            $sessionid = $_COOKIE['sessionid'];

            // Connect to the API
            $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/getSessionUser?sessionid=$sessionid";
       			$ch = curl_init();
      			curl_setopt($ch, CURLOPT_URL, $url);
      			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
      			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
      			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      			$response  = curl_exec($ch);
      			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
       			if ($response === FALSE) {
              $errors[] = "An unexpected error occurred";
              $this->debug('Server Error');
              // In order to prevent recursive calling of audit log function
              if (!$suppressLog){
                  $this->auditlog("session error", "nothing returned from my server");
              }
      			} else {
       				if($httpCode == 400) {
      					// JSON was double-encoded, so it needs to be double decoded
      					$errorsList = json_decode(json_decode($response))->errors;
      					foreach ($errorsList as $err) {
      						$errors[] = $err;
      					}
      					if (sizeof($errors) == 0) {
      						$errors[] = "Bad input";
      					}
       				} else if($httpCode == 500) {
       					$errorsList = json_decode($response)->errors;
      					foreach ($errorsList as $err) {
      						$errors[] = $err;
      					}
      					if (sizeof($errors) == 0) {
      						$errors[] = "Server error";
      					}
       				} else if($httpCode == 200) {
                $user = json_decode($response);
                if(!empty($user)) {
                  if(is_array($user)){
                    $user_array = array("usersessionid"=>$user[0]->usersessionid, "userid"=>$user[0]->userid, "email"=>$user[0]->email, "username"=>$user[0]->username, "registrationcode"=>$user[0]->registrationcode, "isadmin"=>$user[0]->isadmin, "otp"=>$user[0]->otp);
                  } else {
                    $errors[] = $user;
                  }
                }
              }
            }
          }


        return $user_array;

    }

    // Retrieves an existing session from the database for the specified user
    public function isAdmin(&$errors, $userid) {

        // Check for a valid user ID
        if (empty($userid)) {
            $errors[] = "Missing userid";
            return FALSE;
        }

        // Connect to the API
        $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/isAdmin?userid=".$userid;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response  = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($response === FALSE) {
          $errors[] = "An unexpected error occurred";
          $this->debug('Server Error');
          // In order to prevent recursive calling of audit log function
          if (!$suppressLog){
              $this->auditlog("session error", "nothing returned from server");
          }
        } else {
          if($httpCode == 400) {
            // JSON was double-encoded, so it needs to be double decoded
            $errorsList = json_decode(json_decode($response))->errors;
            foreach ($errorsList as $err) {
              $errors[] = $err;
            }
            if (sizeof($errors) == 0) {
              $errors[] = "Bad input";
            }
          } else if($httpCode == 500) {
            $errorsList = json_decode(json_decode($response))->errors;
            foreach ($errorsList as $err) {
              $errors[] = $err;
            }
            if (sizeof($errors) == 0) {
              $errors[] = "Server error";
            }
          } else if($httpCode == 200) {
            // If the query did not run successfully, add an error message to the list
            if ($response === 0) {

                $errors[] = "An unexpected error occurred";
                $this->debug('invalid userid');
                $this->auditlog("isadmin error", 'invalid userid');

                return FALSE;

            } else {
                $flag = json_decode($response);
                $isadmin = $flag[0]->isadmin;

                // Return the isAdmin flag
                return $isadmin == 1;

            }
          }
        }
    }

    // Logs in an existing user and will return the $errors array listing any errors encountered
    public function login($username, $password, &$errors) {

        $this->debug("Login attempted");
        $this->auditlog("login", "attempt: $username, password length = ".strlen($password));

        // Validate the user input
        if (empty($username)) {
            $errors[] = "Missing username";
        }
        if (empty($password)) {
            $errors[] = "Missing password";
        }

        // Only try to query the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {
          $result = "";
          $e_usr = urlencode($username);
            // Connect to the API
            $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/login_user?username=$e_usr";
       			$ch = curl_init();
      			curl_setopt($ch, CURLOPT_URL, $url);
      			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
      			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
      			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      			$response  = curl_exec($ch);
      			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
       			if ($response === FALSE) {
      				$errors[] = "An unexpected failure occurred contacting the web service.";
      			} else {
       				if($httpCode == 400) {
      					// JSON was double-encoded, so it needs to be double decoded
      					$errorsList = json_decode(json_decode($response))->errors;
      					foreach ($errorsList as $err) {
      						$errors[] = $err;
      					}
      					if (sizeof($errors) == 0) {
      						$errors[] = "Bad input";
      					}
       				} else if($httpCode == 500) {
       					$errorsList = json_decode(json_decode($response))->errors;
      					foreach ($errorsList as $err) {
      						$errors[] = $err;
      					}
      					if (sizeof($errors) == 0) {
      						$errors[] = "Server error";
      					}
       				} else if($httpCode == 200) {
       					$result = json_decode($response);
                // If the query did not return any rows, add an error message for bad username/password
                if (empty($result)) {

                    $errors[] = "Bad username/password combination";
                    $this->auditlog("login", "bad username: $username");


                    // If the query ran successfully and we got back a row, then the login succeeded
                } else {

                    // Check the password
                    if (!password_verify($password, $result[0]->passwordhash)) {

                        $errors[] = "Bad username/password combination";
                        $this->auditlog("login", "bad password: password length = ".strlen($password));

                    } else if ($result[0]->emailvalidated != 1) {
                        $errors[] = "Login error. Email not validated. Please check your inbox and/or spam folder.";

                    } else {

                        // Create a new session for this user ID in the database
                        $userid = $result[0]->userid;
                        $sessionid = $this->newSession($userid, $errors);
                        $email = $result[0]->email;
                        $this->auditlog("login", "success: $username, $userid");

                    }

                }
           		}
           	}

        } else {
            $this->auditlog("login validation error", $errors);
        }


        // Return TRUE if there are no errors, otherwise return FALSE
        if ((sizeof($errors) == 0) && (isset($sessionid))){
            return ['sessionid'=>$sessionid, 'email'=>$email];
        } else {
            return FALSE;
        }
    }

    // Logs out the current user based on session ID
    public function logout() {

        $sessionid = $_COOKIE['sessionid'];

        // Only try to query the data into the database if there are no validation errors
        if (!empty($sessionid)) {

              $result = "";
              $data_json = json_encode(array("sessionid"=>$sessionid));
              // Connect to the API
              $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/logout_user";
         			$ch = curl_init();
        			curl_setopt($ch, CURLOPT_URL, $url);
        			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
        			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
              curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
        			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        			$response  = curl_exec($ch);
        			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
              curl_close($ch);
         			if ($response === FALSE) {
        				$errors[] = "An unexpected failure occurred contacting the web service.";
        			} else {
         				if($httpCode == 400) {
        					// JSON was double-encoded, so it needs to be double decoded
        					$errorsList = json_decode(json_decode($response))->errors;
        					foreach ($errorsList as $err) {
        						$errors[] = $err;
        					}
        					if (sizeof($errors) == 0) {
        						$errors[] = "Bad input";
        					}
         				} else if($httpCode == 500) {
         					$errorsList = json_decode(json_decode($response))->errors;
        					foreach ($errorsList as $err) {
        						$errors[] = $err;
        					}
        					if (sizeof($errors) == 0) {
        						$errors[] = "Server error";
        					}
         				} else if($httpCode == 200) {
         					$result = json_decode($response);
                  if ($result === 0) {

                      $this->debug("could not delete from database");
                      $this->auditlog("logout error", "could not delete from database");


                      // If the query ran successfully, then the logout succeeded
                  } else {

                      // Clear the session ID cookie
                      setcookie('sessionid', '', time()-3600);
                      $this->auditlog("logout", "successful: $sessionid");

                  }
         				}
         			}
        }

    }

    // Checks for logged in user and redirects to login if not found with "page=protected" indicator in URL.
    public function protectPage(&$errors, $isAdmin = FALSE, $otp = FALSE) {

        // Get the user ID from the session record
        $user = $this->getSessionUser($errors);

        if ($user == NULL) {
            // Redirect the user to the login page
            $this->auditlog("protect page", "no user");
            header("Location: login.php?page=protected");
            exit();
        } else {
          // Get the user's ID and MFA status
          $userid = $user["userid"];
          $sessionid = $user['usersessionid'];
          $OTP_verification = $user['otp'];
          $this->auditlog("protect page", $OTP_verification);
        }

        // If there is no user ID in the session, then the user is not logged in
        if(empty($userid)) {

            // Redirect the user to the login page
            $this->auditlog("protect page error", $user);
            header("Location: login.php?page=protected");
            exit();

        }
        if(($otp === FALSE) && ($OTP_verification === 0)) { //if the page is not otp.php, verify otp status
          $this->auditlog("protect page", "MFA OTP not complete");
          header("Location: otp.php");
          exit();
        }
        if(($otp === TRUE) && ($OTP_verification === 1)) { //if the page is otp.php, but OTP has already been deleted from table, redirect to list.php
          $this->auditlog("protect page", "MFA OTP already complete");
          header("Location: list.php");
          exit();
        }
         if ($isAdmin)  {

            // Get the isAdmin flag from the database
            $isAdminDB = $this->isAdmin($errors, $userid);

            if (!$isAdminDB) {


                // Redirect the user to the home page
                $this->auditlog("protect page", "not admin");
                header("Location: index.php?page=protectedAdmin");
                exit();

            }

        }
    }

    // Get a list of things from the database and will return the $errors array listing any errors encountered
    public function getThings(&$errors) {

        // Assume an empty list of things
        $things = array();

        // Get the user id from the session
        $user = $this->getSessionUser($errors);
        $registrationcode = $user["registrationcode"];

        // Connect to the API
        $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/getThings?registrationcode=".$registrationcode;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response  = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($response === FALSE) {
          $errors[] = "An unexpected error occurred";
          $this->debug('Server Error');
          // In order to prevent recursive calling of audit log function
          if (!$suppressLog){
              $this->auditlog("session error", "nothing returned from server");
          }
        } else {
          if($httpCode == 400) {
            // JSON was double-encoded, so it needs to be double decoded
            $errorsList = json_decode(json_decode($response))->errors;
            foreach ($errorsList as $err) {
              $errors[] = $err;
            }
            if (sizeof($errors) == 0) {
              $errors[] = "Bad input";
            }
          } else if($httpCode == 500) {
            $errorsList = json_decode(json_decode($response))->errors;
            foreach ($errorsList as $err) {
              $errors[] = $err;
            }
            if (sizeof($errors) == 0) {
              $errors[] = "Server error";
            }
          } else if($httpCode == 200) {
            // If the query did not run successfully, add an error message to the list
            $things_object = json_decode($response);
            if(!empty($things_object)){
              foreach($things_object as $obj){
                $things[] = array("thingid"=>$obj->thingid,"thingname"=>$obj->thingname,"thingcreated"=>$obj->thingcreated, "thingattachmentid"=>$obj->thingattachmentid, "thinguserid"=>$obj->thinguserid, "thingregistrationcode"=>$obj->thingregistrationcode);
              }
            }
          }
        }

        // Return the list of things
        return $things;

    }

    // Get a single thing from the database and will return the $errors array listing any errors encountered
    public function getThing($thingid, &$errors) {

        // Assume no thing exists for this thing id
        $thing = NULL;

        // Check for a valid thing ID
        if (empty($thingid)){
            $errors[] = "Missing thing ID getThing";
        }

        if (sizeof($errors) == 0){

            // Connect to the API
            $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/getThing?thingid=".$thingid;
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response  = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($response === FALSE) {
              $errors[] = "An unexpected error occurred";
              $this->debug('Server Error');
              // In order to prevent recursive calling of audit log function
              if (!$suppressLog){
                  $this->auditlog("session error", "nothing returned from server");
              }
            } else {
              if($httpCode == 400) {
                // JSON was double-encoded, so it needs to be double decoded
                $errorsList = json_decode(json_decode($response))->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Bad input";
                }
              } else if($httpCode == 500) {
                $errorsList = json_decode(json_decode($response))->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Server error";
                }
              } else if($httpCode == 200) {
                // If the query did not run successfully, add an error message to the list
                $thing_object = json_decode($response);
                if ($response === FALSE) {

                    $errors[] = "An unexpected error occurred.";
                    $this->debug('');
                    $this->auditlog("getthing error", $stmt->errorInfo());

                    // If no row returned then the thing does not exist in the database.
                } else if(!empty($thing_object)){
                  $thing = array("thingid"=>$thing_object[0]->thingid,"thingname"=>$thing_object[0]->thingname,"thingcreated"=>$thing_object[0]->thingcreated, "thingattachmentid"=>$thing_object[0]->thingattachmentid, "thinguserid"=>$thing_object[0]->thinguserid, "thingregistrationcode"=>$thing_object[0]->thingregistrationcode,"username"=>$thing_object[0]->username,"filename"=>$thing_object[0]->filename);
                } else {

                    $errors[] = "Thing not found";
                    $this->auditlog("getThing", "bad thing id: $thingid");

                    // If the query ran successfully and row was returned, then get the details of the thing
                }
              }
            }

        } else {
            $this->auditlog("getThing validation error", $errors);
        }

        // Return the thing
        return $thing;

    }

    // Get a list of comments from the database
    public function getComments($thingid, &$errors) {

        // Assume an empty list of comments
        $comments = array();

        // Check for a valid thing ID
        if (empty($thingid)) {

            // Add an appropriate error message to the list
            $errors[] = "Missing thing ID getComments";
            $this->auditlog("getComments validation error", $errors);

        } else {

            // Connect to the API
            $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/getComments?thingid=".$thingid;
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response  = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($response === FALSE) {
              $errors[] = "An unexpected error occurred";
              $this->debug('Server Error');
              // In order to prevent recursive calling of audit log function
              if (!$suppressLog){
                  $this->auditlog("session error", "nothing returned from server");
              }
            } else {
              if($httpCode == 400) {
                // JSON was double-encoded, so it needs to be double decoded
                $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Bad input";
                }
              } else if($httpCode == 500) {
                $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Server error";
                }
              } else if($httpCode == 200) {
                // If the query did not run successfully, add an error message to the list
                $comments_object = json_decode($response);
                if ($response === FALSE) {

                    $errors[] = "An unexpected error occurred.";
                    $this->debug('Query failed to execute');
                    $this->auditlog("getComments error", "query failed to execute");

                    // If no row returned then the thing does not exist in the database.
                } else if(!empty($comments_object)){
                    foreach($comments_object as $obj){
                      $comments[] = array("commentid"=>$obj->commentid,"commenttext"=>$obj->commenttext,"commentposted"=>$obj->commentposted, "username"=>$obj->username, "attachmentid"=>$obj->attachmentid, "filename"=>$obj->filename);
                    }
                }
              }
            }

        }

        // Return the list of comments
        return $comments;

    }

    // Handles the saving of uploaded attachments and the creation of a corresponding record in the attachments table.
    public function saveAttachment($attachment, &$errors) {

        $attachmentid = NULL;

        // Check for an attachment
        if (isset($attachment) && isset($attachment['name']) && !empty($attachment['name'])) {

            // Get the list of valid attachment types and file extensions
            $attachmenttypes = $this->getAttachmentTypes($errors);

            // Construct an array containing only the 'extension' keys
            $extensions = array_column($attachmenttypes, 'extension');

            // Get the uploaded filename
            $filename = $attachment['name'];

            // Extract the uploaded file's extension
            $dot = strrpos($filename, ".");

            // Make sure the file has an extension and the last character of the name is not a "."
            if ($dot !== FALSE && $dot != strlen($filename)) {

                // Check to see if the uploaded file has an allowed file extension
                $extension = strtolower(substr($filename, $dot + 1));
                if (!in_array($extension, $extensions)) {

                    // Not a valid file extension
                    $errors[] = "File does not have a valid file extension";
                    $this->auditlog("saveAttachment", "invalid file extension: $filename");

                }

            } else {

                // No file extension -- Disallow
                $errors[] = "File does not have a valid file extension";
                $this->auditlog("saveAttachment", "no file extension: $filename");

            }

            // Only attempt to add the attachment to the database if the file extension was good
            if (sizeof($errors) == 0) {

                // Create a new ID
                $attachmentid = bin2hex(random_bytes(16));

                // Construct a SQL statement to perform the insert operation
                $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/saveAttachment";
          			$data = array(
          				'attachmentid'=>$attachmentid,
          				'filename'=>$filename
          			);
          			$data_json = json_encode($data);
           			$ch = curl_init();
          			curl_setopt($ch, CURLOPT_URL, $url);
          			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
          			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
          			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
          			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
          			$response  = curl_exec($ch);
          			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
           			if ($response === FALSE) {
          				$errors[] = "An unexpected failure occurred contacting the web service.";
          			} else {
           				if($httpCode == 400) {
          					// JSON was double-encoded, so it needs to be double decoded
          					$errorsList = json_decode(json_decode($response)->errorMessage)->errors;
          					foreach ($errorsList as $err) {
          						$errors[] = $err;
          					}
          					if (sizeof($errors) == 0) {
          						$errors[] = "Bad input";
          					}
           				} else if($httpCode == 500) {
           					$errorsList = json_decode(json_decode($response)->errorMessage)->errors;
          					foreach ($errorsList as $err) {
          						$errors[] = $err;
          					}
          					if (sizeof($errors) == 0) {
          						$errors[] = "Server error";
          					}
           				} else if($httpCode == 200) {
                    // If the query did not run successfully, add an error message to the list
                    if ($response == 0) {
                        $errors[] = "An unexpected error occurred storing the attachment";
                        $this->debug("Server failed to insert session");
                        $this->auditlog("saveAttachment error", "Server failed to insert attachment");
                    } else if($response == 1) {
                        move_uploaded_file($attachment['tmp_name'], getcwd() . '/attachments/' . $attachmentid . '-' . $attachment['name']);
                        $attachmentname = $attachment["name"];
                        $this->auditlog("saveAttachment", "success: $attachmentname");
                    }
           				}
           			}

            }

        }

        return $attachmentid;

    }

    // Adds a new thing to the database
    public function addThing($name, $attachment, &$errors) {

        // Get the user id from the session
        $user = $this->getSessionUser($errors);
        $userid = $user["userid"];
        $registrationcode = $user["registrationcode"];

        // Validate the user input
        if (empty($userid)) {
            $errors[] = "Missing user ID. Not logged in?";
        }
        if (empty($name)) {
            $errors[] = "Missing thing name";
        }

        // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {

            $attachmentid = $this->saveAttachment($attachment, $errors);

            // Only try to insert the data into the database if the attachment successfully saved
            if (sizeof($errors) == 0) {

                // Create a new ID
                $thingid = bin2hex(random_bytes(16));

                // Connect to the API

                $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/addThing";
                $data = array(
                          "thingid"=> $thingid,
                          "thingname"=> $name,
                          "userid"=> $userid,
                          "attachmentid"=> $attachmentid,
                          "registrationcode"=> $registrationcode
                        );
                $data_json = json_encode($data);
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
                curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $response  = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                if ($response === FALSE) {
                  $errors[] = "An unexpected failure occurred contacting the web service.";
                } else {
                  if($httpCode == 400) {
                    // JSON was double-encoded, so it needs to be double decoded
                    $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                    foreach ($errorsList as $err) {
                      $errors[] = $err;
                    }
                    if (sizeof($errors) == 0) {
                      $errors[] = "Bad input";
                    }
                  } else if($httpCode == 500) {
                    $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                    foreach ($errorsList as $err) {
                      $errors[] = $err;
                    }
                    if (sizeof($errors) == 0) {
                      $errors[] = "Server error";
                    }
                  } else if($httpCode == 200) {
                    // If the query did not run successfully, add an error message to the list
                    if ($response == 0) {
                      $errors[] = "An unexpected error occurred adding the thing to the database.";
                      $this->debug("could not add Thing to database");
                      $this->auditlog("addthing error", "Could not insert into database");
                    } else if($response == 1) {
                        $this->auditlog("addthing", "success: $name, id = $thingid");
                    }
                  }
                }

            }

        } else {
            $this->auditlog("addthing validation error", $errors);
        }

        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }

    // Adds a new comment to the database
    public function addComment($text, $thingid, $attachment, &$errors) {

        // Get the user id from the session
        $user = $this->getSessionUser($errors);
        $userid = $user["userid"];

        // Validate the user input
        if (empty($userid)) {
            $errors[] = "Missing user ID. Not logged in?";
        }
        if (empty($thingid)) {
            $errors[] = "Missing thing ID addComment";
        }
        if (empty($text)) {
            $errors[] = "Missing comment text";
        }

        // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {

            $attachmentid = $this->saveAttachment($attachment, $errors);

            // Only try to insert the data into the database if the attachment successfully saved
            if (sizeof($errors) == 0) {

                // Create a new ID
                $commentid = bin2hex(random_bytes(16));

                $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/addComment";
                $data = array(
                          "commentid"=> $commentid,
                          "commenttext"=> $text,
                          "userid"=> $userid,
                          "attachmentid"=> $attachmentid,
                          "thingid"=> $thingid
                        );
                $data_json = json_encode($data);
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
                curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $response  = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                if ($response === FALSE) {
                  $errors[] = "An unexpected failure occurred contacting the web service.";
                } else {
                  if($httpCode == 400) {
                    // JSON was double-encoded, so it needs to be double decoded
                    $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                    foreach ($errorsList as $err) {
                      $errors[] = $err;
                    }
                    if (sizeof($errors) == 0) {
                      $errors[] = "Bad input";
                    }
                  } else if($httpCode == 500) {
                    $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                    foreach ($errorsList as $err) {
                      $errors[] = $err;
                    }
                    if (sizeof($errors) == 0) {
                      $errors[] = "Server error";
                    }
                  } else if($httpCode == 200) {
                    // If the query did not run successfully, add an error message to the list
                    if ($response == 0) {
                      $errors[] = "An unexpected error occurred adding the comment to the database.";
                      $this->debug("could not add comment to database");
                      $this->auditlog("addComment error", "Could not insert into database");
                    } else if($response == 1) {
                      $this->auditlog("addcomment", "success: $commentid");
                    }
                  }
                }

            }

        } else {
            $this->auditlog("addcomment validation error", $errors);
        }

        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }

    // Get a list of users from the database and will return the $errors array listing any errors encountered
    public function getUsers(&$errors) {

        // Assume an empty list of topics
        $users = array();

        // Connect to the API
        $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/getUsers";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response  = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($response === FALSE) {
          $errors[] = "An unexpected error occurred";
          $this->debug('Server Error');
          // In order to prevent recursive calling of audit log function
          if (!$suppressLog){
              $this->auditlog("session error", "nothing returned from server");
          }
        } else {
          if($httpCode == 400) {
            // JSON was double-encoded, so it needs to be double decoded
            $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
            foreach ($errorsList as $err) {
              $errors[] = $err;
            }
            if (sizeof($errors) == 0) {
              $errors[] = "Bad input";
            }
          } else if($httpCode == 500) {
            $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
            foreach ($errorsList as $err) {
              $errors[] = $err;
            }
            if (sizeof($errors) == 0) {
              $errors[] = "Server error";
            }
          } else if($httpCode == 200) {
            // If the query did not run successfully, add an error message to the list
            $users_object = json_decode($response);
            if ($response === FALSE) {

                $errors[] = "An unexpected error occurred.";
                $this->debug('Query failed to execute');
                $this->auditlog("getUsers error", "query failed to execute");

                // If no row returned then the thing does not exist in the database.
            } else if(!empty($users_object)){
                foreach($users_object as $obj){
                  $users[] = array("userid"=>$obj->userid, "username"=>$obj->username, "email"=>$obj->email, "isadmin"=>$obj->isadmin);
                }
            }
          }
        }

        // Return the list of users
        return $users;

    }

    // Gets a single user from database and will return the $errors array listing any errors encountered
    public function getUser($userid, &$errors) {

        // Assume no user exists for this user id
        $user = NULL;

        // Validate the user input
        if (empty($userid)) {
            $errors[] = "Missing userid";
        }

        if(sizeof($errors)== 0) {

            // Get the user id from the session
            $user = $this->getSessionUser($errors);
            $loggedinuserid = $user["userid"];
            $isadmin = FALSE;

            // Check to see if the user really is logged in and really is an admin
            if ($loggedinuserid != NULL) {
                $isadmin = $this->isAdmin($errors, $loggedinuserid);
            }

            // Stop people from viewing someone else's profile
            if (!$isadmin && $loggedinuserid != $userid) {

                $errors[] = "Cannot view other user";
                $this->auditlog("getuser", "attempt to view other user: $loggedinuserid");

            } else {

                // Only try to insert the data into the database if there are no validation errors
                if (sizeof($errors) == 0) {

                    // Connect to the database
                    $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/getUser?userid=$userid";
                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, $url);
                    curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
                    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    $response  = curl_exec($ch);
                    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    curl_close($ch);
                    if ($response === FALSE) {
                      $errors[] = "An unexpected error occurred";
                      $this->debug('Server Error');
                      // In order to prevent recursive calling of audit log function
                      if (!$suppressLog){
                          $this->auditlog("session error", "nothing returned from server");
                      }
                    } else {
                      if($httpCode == 400) {
                        // JSON was double-encoded, so it needs to be double decoded
                        $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                        foreach ($errorsList as $err) {
                          $errors[] = $err;
                        }
                        if (sizeof($errors) == 0) {
                          $errors[] = "Bad input";
                        }
                      } else if($httpCode == 500) {
                        $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                        foreach ($errorsList as $err) {
                          $errors[] = $err;
                        }
                        if (sizeof($errors) == 0) {
                          $errors[] = "Server error";
                        }
                      } else if($httpCode == 200) {
                        // If the query did not run successfully, add an error message to the list
                        $user_object = json_decode($response);
                        if ($response === FALSE) {

                            $errors[] = "An unexpected error occurred.";
                            $this->debug('Query failed to execute');
                            $this->auditlog("getUser error", "query failed to execute");

                            // If no row returned then the thing does not exist in the database.
                        } else if(!empty($user_object)){
                            $user = array("userid"=>$user_object[0]->userid, "username"=>$user_object[0]->username, "email"=>$user_object[0]->email, "isadmin"=>$user_object[0]->isadmin);
                            $this->auditlog("getusers", "success");
                        } else {

                            $errors[] = "Bad userid";
                            $this->auditlog("getuser", "bad userid: $userid");

                            // If the query ran successfully and we got back a row, then the request succeeded
                        }
                      }
                    }

                } else {
                    $this->auditlog("getuser validation error", $errors);
                }
            }
        } else {
            $this->auditlog("getuser validation error", $errors);
        }

        // Return user if there are no errors, otherwise return NULL
        return $user;
    }


    // Updates a single user in the database and will return the $errors array listing any errors encountered
    public function updateUser($userid, $username, $email, $password, $isadminDB, &$errors) {

        // Assume no user exists for this user id
        $user = NULL;
        // Validate the user input
        if (empty($userid)) {

            $errors[] = "Missing userid";

        }

        if(sizeof($errors) == 0) {

            // Get the user id from the session
            $user = $this->getSessionUser($errors);
            $loggedinuserid = $user["userid"];
            $isadmin = FALSE;

            // Check to see if the user really is logged in and really is an admin
            if ($loggedinuserid != NULL) {
                $isadmin = $this->isAdmin($errors, $loggedinuserid);
            }

            // Stop people from editing someone else's profile
            if (!$isadmin && $loggedinuserid != $userid) {

                $errors[] = "Cannot edit other user";
                $this->auditlog("getuser", "attempt to update other user: $loggedinuserid");

            } else {

                // Validate the user input
                if (empty($userid)) {
                    $errors[] = "Missing userid";
                }
                if (empty($username)) {
                    $errors[] = "Missing username";
                }
                if (empty($email)) {
                    $errors[] = "Missing email;";
                }

                $this->validateUsername($username, $errors);
                if(isset($password)&&(!empty($password))){
                  $this->validatePassword($password, $errors);
                }
                $this->validateEmail($email, $errors);
                // Only try to update the data into the database if there are no validation errors
                if (sizeof($errors) == 0) {

                  $user_info = array("userid"=>$userid,"username"=>$username,"email"=>$email);
                  $adminFlag = ($isadminDB ? "1" : "0");
                  if ($loggedinuserid != $userid) {
                      $user_info['isadmin'] = $adminFlag;
                  }
                  if(isset($password)&&(!empty($password))) {
                    $passwordhash = password_hash($password, PASSWORD_DEFAULT);
                    $user_info['passwordhash'] = $passwordhash;
                  }

                  $success = FALSE;
                  // Connect to the API
                  $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/updateUser";
            			$data_json = json_encode($user_info);
             			$ch = curl_init();
            			curl_setopt($ch, CURLOPT_URL, $url);
            			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
            			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
            			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
            			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            			$response  = curl_exec($ch);
            			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                  curl_close($ch);
             			if ($response === FALSE) {
            				$errors[] = "An unexpected failure occurred contacting the web service.";
            			} else {
             				if($httpCode == 400) {
            					// JSON was double-encoded, so it needs to be double decoded
            					$errorsList = json_decode(json_decode($response)->errorMessage)->errors;
            					foreach ($errorsList as $err) {
            						$errors[] = $err;
            					}
            					if (sizeof($errors) == 0) {
            						$errors[] = "Bad input";
            					}
             				} else if($httpCode == 500) {
             					$errorsList = json_decode(json_decode($response)->errorMessage)->errors;
            					foreach ($errorsList as $err) {
            						$errors[] = $err;
            					}
            					if (sizeof($errors) == 0) {
            						$errors[] = "Server error";
            					}
             				} else if($httpCode == 200) {
                      if ($response == 0) {
                          $errors[] = "An unexpected error occurred updating the user info";
                          $this->auditlog("updateUser error", "Update query affected 0 rows");
                      } else if($response == 1) {
                        $success = TRUE;
                        $this->auditlog("updateUser", "success");
                      } else {
                        $errors[] = $response;
                        $this->debug("Unexpected result $response");
                        $this->auditlog("updateUser", "Invalid request: $userid");
                      }
                    }
                  }

                } else {
                    $this->auditlog("updateUser validation error", $errors);
                }
            }
        } else {
            $this->auditlog("updateUser validation error", $errors);
        }

        // Return TRUE if there are no errors, otherwise return FALSE
        return $success;
    }

    // Validates a provided username or email address and sends a password reset email
    public function passwordReset($usernameOrEmail, &$errors) {

        // Check for a valid username/email
        if (empty($usernameOrEmail)) {
            $errors[] = "Missing username/email";
            $this->auditlog("session", "missing username");
        }

        // Only proceed if there are no validation errors
        if (sizeof($errors) == 0) {
            $passwordresetid = bin2hex(random_bytes(16));
            // Connect to the API
            $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/passwordReset";
            $data = array(
                      "passwordresetid"=> $passwordresetid,
                      "usernameOrEmail"=> $usernameOrEmail
                    );
            $data_json = json_encode($data);
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response  = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($response === FALSE) {
              $errors[] = "An unexpected failure occurred contacting the web service.";
            } else {
              if($httpCode == 400) {
                // JSON was double-encoded, so it needs to be double decoded
                $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Bad input";
                }
              } else if($httpCode == 500) {
                $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Server error";
                }
              } else if($httpCode == 200) {
                // If the query did not run successfully, add an error message to the list
                if (empty($response)) {
                  $errors[] = "An unexpected error occurred with the database.";
                  $this->debug("could not add passwordresetid to database");
                  $this->auditlog("resetPassword error", "Could not insert into database");
                } else {
                  $email = $response;
                  $this->auditlog("passwordReset", "Sending message to $email");

                  // Send reset email
                  $pageLink = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
                  $pageLink = str_replace("reset.php", "password.php", $pageLink);
                  $to      = $email;
                  $subject = 'Password reset';
                  $message = "A password reset request for this account has been submitted at https://russellthackston.me. ".
                      "If you did not make this request, please ignore this message. No other action is necessary. ".
                      "To reset your password, please click the following link: $pageLink?id=$passwordresetid";
                  $headers = 'From: webmaster@russellthackston.me' . "\r\n" .
                      'Reply-To: webmaster@russellthackston.me' . "\r\n";

                  mail($to, $subject, $message, $headers);

                  $this->auditlog("passwordReset", "Message sent to $email");
                }
              }
            }

        }

    }

    // Validates a provided username or email address and sends a password reset email
    public function updatePassword($password, $passwordresetid, &$errors) {

        // Check for a valid username/email
        $this->validatePassword($password, $errors);
        if (empty($passwordresetid)) {
            $errors[] = "Missing passwordrequestid";
        }

        // Only proceed if there are no validation errors
        if (sizeof($errors) == 0) {

            // Connect to the API
            $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/updatePassword?passwordresetid=$passwordresetid";
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response  = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($response === FALSE) {
              $errors[] = "An unexpected error occurred";
              $this->debug('Server Error');
              // In order to prevent recursive calling of audit log function
              if (!$suppressLog){
                  $this->auditlog("session error", "nothing returned from server");
              }
            } else {
              if($httpCode == 400) {
                // JSON was double-encoded, so it needs to be double decoded
                $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Bad input";
                }
              } else if($httpCode == 500) {
                $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Server error";
                }
              } else if($httpCode == 200) {
                // If the query did not run successfully, add an error message to the list
                $userid_obj = json_decode($response);
                if ($response === FALSE) {

                    $errors[] = "An unexpected error occurred.";
                    $this->debug('Query failed to execute');
                    $this->auditlog("updatePassword error", "query failed to execute");

                    // If no row returned then the thing does not exist in the database.
                } else if(!empty($userid_obj)){
                    $userid = $userid_obj[0]->userid;
                    $this->updateUserPassword($userid, $password, $errors);
                    $this->clearPasswordResetRecords($passwordresetid);
                } else {

                    $errors[] = "Bad passwordresetid";
                    $this->auditlog("updatePassword", "bad passwordresetid: $passwordresetid");

                    // If the query ran successfully and we got back a row, then the request succeeded
                }
              }
            }

        }

    }

    function getFile($name){
        return file_get_contents($name);
    }

    // Get a list of users from the database and will return the $errors array listing any errors encountered
    public function getAttachmentTypes(&$errors) {

        // Assume an empty list of topics
        $types = array();

        // Connect to the API
        $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/getAttachmentTypes";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k'));
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response  = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($response === FALSE) {
          $errors[] = "An unexpected error occurred";
          $this->debug('Server Error');
          // In order to prevent recursive calling of audit log function
          if (!$suppressLog){
              $this->auditlog("session error", "nothing returned from server");
          }
        } else {
          if($httpCode == 400) {
            // JSON was double-encoded, so it needs to be double decoded
            $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
            foreach ($errorsList as $err) {
              $errors[] = $err;
            }
            if (sizeof($errors) == 0) {
              $errors[] = "Bad input";
            }
          } else if($httpCode == 500) {
            $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
            foreach ($errorsList as $err) {
              $errors[] = $err;
            }
            if (sizeof($errors) == 0) {
              $errors[] = "Server error";
            }
          } else if($httpCode == 200) {
            // If the query did not run successfully, add an error message to the list
            $attachmenttypes_object = json_decode($response);
            if ($response === FALSE) {

                $errors[] = "An unexpected error occurred getting the attachment types list.";
                $this->debug('Query failed to execute');
                $this->auditlog("getattachmenttypes error", "query failed to execute");

                // If no row returned then the thing does not exist in the database.
            } else if(!empty($attachmenttypes_object)){
                foreach($attachmenttypes_object as $obj){
                  $types[] = array("attachmenttypeid"=>$obj->attachmenttypeid, "name"=>$obj->name, "extension"=>$obj->extension);
                }
                $this->auditlog("getattachmenttypes", "success");
            }
          }
        }
        // Return the list of users
        return $types;

    }

    // Creates a new session in the database for the specified user
    public function newAttachmentType($name, $extension, &$errors) {

        $attachmenttypeid = NULL;

        // Check for a valid name
        if (empty($name)) {
            $errors[] = "Missing name";
        }
        // Check for a valid extension
        if (empty($extension)) {
            $errors[] = "Missing extension";
        }

        // Only try to query the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {

            // Create a new session ID
            $attachmenttypeid = bin2hex(random_bytes(25));

            $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/newAttachmentType";
            $data = array(
                      "attachmenttypeid"=> $attachmenttypeid,
                      "name"=> $name,
                      "extension"=> $extension
                    );
            $data_json = json_encode($data);
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response  = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($response === FALSE) {
              $errors[] = "An unexpected failure occurred contacting the web service.";
            } else {
              if($httpCode == 400) {
                // JSON was double-encoded, so it needs to be double decoded
                $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Bad input";
                }
              } else if($httpCode == 500) {
                $errorsList = json_decode(json_decode($response)->errorMessage)->errors;
                foreach ($errorsList as $err) {
                  $errors[] = $err;
                }
                if (sizeof($errors) == 0) {
                  $errors[] = "Server error";
                }
              } else if($httpCode == 200) {
                // If the query did not run successfully, add an error message to the list
                if ($response === 0 || $response === FALSE) {
                  $errors[] = "An unexpected error occurred adding the attachment type to the database.";
                  $this->debug("could not add attachment type to database");
                  $this->auditlog("newAttachmentType error", "Could not insert into database");
                  return NULL;
                } else if($response == 1) {
                  $this->auditlog("addcomment", "success: $commentid");
                }
              }
            }

        } else {

            $this->auditlog("newAttachmentType error", $errors);
            return NULL;

        }

        return $attachmenttypeid;
    }

    //stores a randomly generated OTP in the databse and sends user an email with the same OTP
    public function create_otp($email, $sessionid, &$errors){

      if (empty($sessionid)) {
          $errors[] = "Missing sessionid";
      }
      if(sizeof($errors) == 0){
        $dbh = $this->getConnection();

        $otp = bin2hex(random_bytes(3));

        // Construct a SQL statement to perform the insert operation
        $sql = "INSERT INTO OTP (otp, sessionid, date) VALUES (:otp, :sessionid, NOW());";

        // Run the SQL select and capture the result code
        $stmt = $dbh->prepare($sql);
        $stmt->bindParam(":otp", $otp);
        $stmt->bindParam(":sessionid", $sessionid);
        $result = $stmt->execute();
        $dbh  = NULL;
        // If the query did not run successfully, add an error message to the list
        if ($result === FALSE) {

            $errors[] = "An unexpected error occurred";
            $this->debug($stmt->errorInfo());
            $this->auditlog("otp insert error", $stmt->errorInfo());
            return FALSE;
        } else {
          $this->auditlog("OTP", "Sending message to $email");

          // Send reset email
          $pageLink = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
          $pageLink = str_replace("login.php", "otp.php", $pageLink);
          $to = $email;
          $subject = 'Login One Time Password';
          $message = "A request has been made to login to https://jonathanhuling.me for this email address. ".
              "If you did not make this request, please ignore this message. No other action is necessary. ".
              "To confirm the login, please click the following link: $pageLink, or copy and paste it into your browser. Then, copy and paste the following One Time Password when prompted: $otp";
          $headers = 'From: no-reply@jonathanhuling.me' . "\r\n";

          mail($to, $subject, $message, $headers);

          $this->auditlog("OTP", "Message sent to $email");
          return TRUE;
        }
      } else {
          $this->auditlog("missing otp parameters", $errors);
          return FALSE;
      }
    }

    public function verify_otp($otp, $sessionid){
      $dbh = $this->getConnection();

  		$sql = "DELETE FROM OTP WHERE otp = :otp AND sessionid = :sessionid";

  		$stmt = $dbh->prepare($sql);
  		$stmt->bindParam(":otp", $otp);
  		$stmt->bindParam(":sessionid", $sessionid);
  		$stmt->execute();
      $result = $stmt->rowCount();
      if($result == 0){
        return $result;
      } else if($result > 0){
        $sql = "UPDATE usersessions SET otp=1 WHERE usersessionid = :sessionid";
        $stmt = $dbh->prepare($sql);
    		$stmt->bindParam(":sessionid", $sessionid);
    		$stmt->execute();
        $dbh = NULL;
        return $stmt->rowCount();
      } else {
        return 0;
      }
    }
}


?>
