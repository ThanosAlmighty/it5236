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

			curl_close($ch);
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

  			curl_close($ch);

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
        curl_close($ch);
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

      			curl_close($ch);
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

		curl_close($ch);
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
            curl_close($ch);

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
      			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
      			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
      			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      			$response  = curl_exec($ch);
      			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
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
       					$errorsList = json_decode(json_decode($response))->errors;
      					foreach ($errorsList as $err) {
      						$errors[] = $err;
      					}
      					if (sizeof($errors) == 0) {
      						$errors[] = "Server error";
      					}
       				} else if($httpCode == 200) {
                $user = json_decode($response);
                if(!empty($response)) {
                  $user_array = ["usersessionid"=>$user[0]->usersessionid, "userid"=>$user[0]->userid, "email"=>$user[0]->email, "username"=>$user[0]->username, "registrationcode"=>$user[0]->registrationcode, "isadmin"=>$user[0]->isadmin];
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
        $url = "https://s1zjxnaf6g.execute-api.us-east-1.amazonaws.com/default/isAdmin?userid=$userid";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response  = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
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
            $errorsList = json_decode(json_decode($response))->errors;
            foreach ($errorsList as $err) {
              $errors[] = $err;
            }
            if (sizeof($errors) == 0) {
              $errors[] = "Server error";
            }
          } else if($httpCode == 200) {
            // If the query did not run successfully, add an error message to the list
            if ($reponse == 0) {

                $errors[] = "An unexpected error occurred";
                $this->debug('invalid userid');
                $this->auditlog("isadmin error", 'invalid userid');

                return FALSE;

            } else {

                $isadmin = json_decode($response)[0]->isadmin;

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
      			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'x-api-key: DUQ6bDCCCp6pNaYCJKpbl5hS5Yb0K4J710vrHp1k','Content-Length: ' . strlen($data_json)));
      			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
      			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      			$response  = curl_exec($ch);
      			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
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

      			curl_close($ch);

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

                      $this->debug($stmt->errorInfo());
                      $this->auditlog("logout error", $stmt->errorInfo());


                      // If the query ran successfully, then the logout succeeded
                  } else {

                      // Clear the session ID cookie
                      setcookie('sessionid', '', time()-3600);
                      $this->auditlog("logout", "successful: $sessionid");

                  }
         				}
         			}
        			curl_close($ch);
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
        }

        // Get the user's ID and MFA status
        $userid = $user["userid"];
        $sessionid = $user['usersessionid'];

        $dbh = $this->getConnection();

        $sql = "SELECT sessionid FROM OTP WHERE sessionid = :sessionid";

        $stmt = $dbh->prepare($sql);
        $stmt->bindParam(":sessionid", $sessionid);
        $stmt->execute();
        $OTP_verification = $stmt->rowCount();
        $dbh = NULL;

        // If there is no user ID in the session, then the user is not logged in
        if(empty($userid)) {

            // Redirect the user to the login page
            $this->auditlog("protect page error", $user);
            header("Location: login.php?page=protected");
            exit();

        } else if(($otp === FALSE) && ($OTP_verification > 0)) { //if the page is not otp.php, verify otp status
          $this->auditlog("protect page", "MFA OTP not complete");
          header("Location: otp.php");
          exit();
        } else if(($otp === TRUE) && ($OTP_verification == 0)) { //if the page is otp.php, but OTP has already been deleted from table, redirect to list.php
          $this->auditlog("protect page", "MFA OTP already complete");
          header("Location: list.php");
          exit();
        } else if ($isAdmin)  {

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

        // Connect to the database
        $dbh = $this->getConnection();

        // Get the user id from the session
        $user = $this->getSessionUser($errors);
        $registrationcode = $user["registrationcode"];

        // Construct a SQL statement to perform the select operation
        $sql = "SELECT thingid, thingname, convert_tz(things.thingcreated,@@session.time_zone,'America/New_York') as thingcreated, thinguserid, thingattachmentid, thingregistrationcode FROM things LEFT JOIN users ON things.thinguserid = users.userid WHERE thingregistrationcode = :registrationcode ORDER BY things.thingcreated ASC";

        // Run the SQL select and capture the result code
        $stmt = $dbh->prepare($sql);
        $stmt->bindParam(":registrationcode", $registrationcode);
        $result = $stmt->execute();

        // If the query did not run successfully, add an error message to the list
        if ($result === FALSE) {

            $errors[] = "An unexpected error occurred.";
            $this->debug($stmt->errorInfo());
            $this->auditlog("getthings error", $stmt->errorInfo());

            // If the query ran successfully, then get the list of things
        } else {

            // Get all the rows
            $things = $stmt->fetchAll();

        }

        // Close the connection
        $dbh = NULL;

        // Return the list of things
        return $things;

    }

    // Get a single thing from the database and will return the $errors array listing any errors encountered
    public function getThing($thingid, &$errors) {

        // Assume no thing exists for this thing id
        $thing = NULL;

        // Check for a valid thing ID
        if (empty($thingid)){
            $errors[] = "Missing thing ID";
        }

        if (sizeof($errors) == 0){

            // Connect to the database
            $dbh = $this->getConnection();

            // Construct a SQL statement to perform the select operation
            $sql = "SELECT things.thingid, things.thingname, convert_tz(things.thingcreated,@@session.time_zone,'America/New_York') as thingcreated, things.thinguserid, things.thingattachmentid, things.thingregistrationcode, username, filename " .
                "FROM things LEFT JOIN users ON things.thinguserid = users.userid " .
                "LEFT JOIN attachments ON things.thingattachmentid = attachments.attachmentid " .
                "WHERE thingid = :thingid";

            // Run the SQL select and capture the result code
            $stmt = $dbh->prepare($sql);
            $stmt->bindParam(":thingid", $thingid);
            $result = $stmt->execute();

            // If the query did not run successfully, add an error message to the list
            if ($result === FALSE) {

                $errors[] = "An unexpected error occurred.";
                $this->debug($stmt->errorInfo());
                $this->auditlog("getthing error", $stmt->errorInfo());

                // If no row returned then the thing does not exist in the database.
            } else if ($stmt->rowCount() == 0) {

                $errors[] = "Thing not found";
                $this->auditlog("getThing", "bad thing id: $thingid");

                // If the query ran successfully and row was returned, then get the details of the thing
            } else {

                // Get the thing
                $thing = $stmt->fetch();

            }

            // Close the connection
            $dbh = NULL;

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
            $errors[] = "Missing thing ID";
            $this->auditlog("getComments validation error", $errors);

        } else {

            // Connect to the database
            $dbh = $this->getConnection();

            // Construct a SQL statement to perform the select operation
            $sql = "SELECT commentid, commenttext, convert_tz(comments.commentposted,@@session.time_zone,'America/New_York') as commentposted, username, attachmentid, filename " .
                "FROM comments LEFT JOIN users ON comments.commentuserid = users.userid " .
                "LEFT JOIN attachments ON comments.commentattachmentid = attachments.attachmentid " .
                "WHERE commentthingid = :thingid ORDER BY commentposted ASC";

            // Run the SQL select and capture the result code
            $stmt = $dbh->prepare($sql);
            $stmt->bindParam(":thingid", $thingid);
            $result = $stmt->execute();

            // If the query did not run successfully, add an error message to the list
            if ($result === FALSE) {

                $errors[] = "An unexpected error occurred loading the comments.";
                $this->debug($stmt->errorInfo());
                $this->auditlog("getcomments error", $stmt->errorInfo());

                // If the query ran successfully, then get the list of comments
            } else {

                // Get all the rows
                $comments = $stmt->fetchAll();

            }

            // Close the connection
            $dbh = NULL;

        }

        // Return the list of comments
        return $comments;

    }

    // Handles the saving of uploaded attachments and the creation of a corresponding record in the attachments table.
    public function saveAttachment($dbh, $attachment, &$errors) {

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
                $sql = "INSERT INTO attachments (attachmentid, filename) VALUES (:attachmentid, :filename)";

                // Run the SQL insert and capture the result code
                $stmt = $dbh->prepare($sql);
                $stmt->bindParam(":attachmentid", $attachmentid);
                $stmt->bindParam(":filename", $filename);
                $result = $stmt->execute();

                // If the query did not run successfully, add an error message to the list
                if ($result === FALSE) {

                    $errors[] = "An unexpected error occurred storing the attachment.";
                    $this->debug($stmt->errorInfo());
                    $this->auditlog("saveAttachment error", $stmt->errorInfo());

                } else {

                    // Move the file from temp folder to html attachments folder
                    move_uploaded_file($attachment['tmp_name'], getcwd() . '/attachments/' . $attachmentid . '-' . $attachment['name']);
                    $attachmentname = $attachment["name"];
                    $this->auditlog("saveAttachment", "success: $attachmentname");

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

            // Connect to the database
            $dbh = $this->getConnection();
            $attachmentid = $this->saveAttachment($dbh, $attachment, $errors);

            // Only try to insert the data into the database if the attachment successfully saved
            if (sizeof($errors) == 0) {

                // Create a new ID
                $thingid = bin2hex(random_bytes(16));

                // Add a record to the things table
                // Construct a SQL statement to perform the insert operation
                $sql = "INSERT INTO things (thingid, thingname, thingcreated, thinguserid, thingattachmentid, thingregistrationcode) VALUES (:thingid, :name, now(), :userid, :attachmentid, :registrationcode)";

                // Run the SQL insert and capture the result code
                $stmt = $dbh->prepare($sql);
                $stmt->bindParam(":thingid", $thingid);
                $stmt->bindParam(":name", $name);
                $stmt->bindParam(":userid", $userid);
                $stmt->bindParam(":attachmentid", $attachmentid);
                $stmt->bindParam(":registrationcode", $registrationcode);
                $result = $stmt->execute();

                // If the query did not run successfully, add an error message to the list
                if ($result === FALSE) {

                    $errors[] = "An unexpected error occurred adding the thing to the database.";
                    $this->debug($stmt->errorInfo());
                    $this->auditlog("addthing error", $stmt->errorInfo());

                } else {

                    $this->auditlog("addthing", "success: $name, id = $thingid");

                }

            }

            // Close the connection
            $dbh = NULL;

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
            $errors[] = "Missing thing ID";
        }
        if (empty($text)) {
            $errors[] = "Missing comment text";
        }

        // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {

            // Connect to the database
            $dbh = $this->getConnection();

            $attachmentid = $this->saveAttachment($dbh, $attachment, $errors);

            // Only try to insert the data into the database if the attachment successfully saved
            if (sizeof($errors) == 0) {

                // Create a new ID
                $commentid = bin2hex(random_bytes(16));

                // Add a record to the Comments table
                // Construct a SQL statement to perform the insert operation
                $sql = "INSERT INTO comments (commentid, commenttext, commentposted, commentuserid, commentthingid, commentattachmentid) " .
                "VALUES (:commentid, :text, now(), :userid, :thingid, :attachmentid)";

                // Run the SQL insert and capture the result code
                $stmt = $dbh->prepare($sql);
                $stmt->bindParam(":commentid", $commentid);
                $stmt->bindParam(":text", $text);
                $stmt->bindParam(":userid", $userid);
                $stmt->bindParam(":thingid", $thingid);
                $stmt->bindParam(":attachmentid", $attachmentid);
                $result = $stmt->execute();

                // If the query did not run successfully, add an error message to the list
                if ($result === FALSE) {
                    $errors[] = "An unexpected error occurred saving the comment to the database.";
                    $this->debug($stmt->errorInfo());
                    $this->auditlog("addcomment error", $stmt->errorInfo());
                } else {
                    $this->auditlog("addcomment", "success: $commentid");
                }

            }

            // Close the connection
            $dbh = NULL;

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

        // Connect to the database
        $dbh = $this->getConnection();

        // Construct a SQL statement to perform the select operation
        $sql = "SELECT userid, username, email, isadmin FROM users ORDER BY username";

        // Run the SQL select and capture the result code
        $stmt = $dbh->prepare($sql);
        $result = $stmt->execute();

        // If the query did not run successfully, add an error message to the list
        if ($result === FALSE) {

            $errors[] = "An unexpected error occurred getting the user list.";
            $this->debug($stmt->errorInfo());
            $this->auditlog("getusers error", $stmt->errorInfo());

            // If the query ran successfully, then get the list of users
        } else {

            // Get all the rows
            $users = $stmt->fetchAll();
            $this->auditlog("getusers", "success");

        }

        // Close the connection
        $dbh = NULL;

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
                    $dbh = $this->getConnection();

                    // Construct a SQL statement to perform the select operation
                    $sql = "SELECT userid, username, email, isadmin FROM users WHERE userid = :userid";

                    // Run the SQL select and capture the result code
                    $stmt = $dbh->prepare($sql);
                    $stmt->bindParam(":userid", $userid);
                    $result = $stmt->execute();

                    // If the query did not run successfully, add an error message to the list
                    if ($result === FALSE) {

                        $errors[] = "An unexpected error occurred retrieving the specified user.";
                        $this->debug($stmt->errorInfo());
                        $this->auditlog("getuser error", $stmt->errorInfo());

                        // If the query did not return any rows, add an error message for invalid user id
                    } else if ($stmt->rowCount() == 0) {

                        $errors[] = "Bad userid";
                        $this->auditlog("getuser", "bad userid: $userid");

                        // If the query ran successfully and we got back a row, then the request succeeded
                    } else {

                        // Get the row from the result
                        $user = $stmt->fetch();

                    }

                    // Close the connection
                    $dbh = NULL;

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

                // Only try to update the data into the database if there are no validation errors
                if (sizeof($errors) == 0) {

                    // Connect to the database
                    $dbh = $this->getConnection();

                    // Hash the user's password
                    $passwordhash = password_hash($password, PASSWORD_DEFAULT);

                    // Construct a SQL statement to perform the select operation
                    $sql = 	"UPDATE users SET username=:username, email=:email " .
                        ($loggedinuserid != $userid ? ", isadmin=:isAdmin " : "") .
                        (!empty($password) ? ", passwordhash=:passwordhash" : "") .
                        " WHERE userid = :userid";

                        // Run the SQL select and capture the result code
                        $stmt = $dbh->prepare($sql);
                        $stmt->bindParam(":username", $username);
                        $stmt->bindParam(":email", $email);
                        $adminFlag = ($isadminDB ? "1" : "0");
                        if ($loggedinuserid != $userid) {
                            $stmt->bindParam(":isAdmin", $adminFlag);
                        }
                        if (!empty($password)) {
                            $stmt->bindParam(":passwordhash", $passwordhash);
                        }
                        $stmt->bindParam(":userid", $userid);
                        $result = $stmt->execute();

                        // If the query did not run successfully, add an error message to the list
                        if ($result === FALSE) {
                            $errors[] = "An unexpected error occurred saving the user profile. ";
                            $this->debug($stmt->errorInfo());
                            $this->auditlog("updateUser error", $stmt->errorInfo());
                        } else {
                            $this->auditlog("updateUser", "success");
                        }

                        // Close the connection
                        $dbh = NULL;
                } else {
                    $this->auditlog("updateUser validation error", $errors);
                }
            }
        } else {
            $this->auditlog("updateUser validation error", $errors);
        }

        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
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

            // Connect to the database
            $dbh = $this->getConnection();

            // Construct a SQL statement to perform the insert operation
            $sql = "SELECT email, userid FROM users WHERE username = :username OR email = :email";

            // Run the SQL select and capture the result code
            $stmt = $dbh->prepare($sql);
            $stmt->bindParam(":username", $usernameOrEmail);
            $stmt->bindParam(":email", $usernameOrEmail);
            $result = $stmt->execute();

            // If the query did not run successfully, add an error message to the list
            if ($result === FALSE) {

                $this->auditlog("passwordReset error", $stmt->errorInfo());
                $errors[] = "An unexpected error occurred saving your request to the database.";
                $this->debug($stmt->errorInfo());

            } else {

                if ($stmt->rowCount() == 1) {

                    $row = $stmt->fetch(PDO::FETCH_ASSOC);

                    $passwordresetid = bin2hex(random_bytes(16));
                    $userid = $row['userid'];
                    $email = $row['email'];

                    // Construct a SQL statement to perform the insert operation
                    $sql = "INSERT INTO passwordreset (passwordresetid, userid, email, expires) " .
                        "VALUES (:passwordresetid, :userid, :email, DATE_ADD(NOW(), INTERVAL 1 HOUR))";

                    // Run the SQL select and capture the result code
                    $stmt = $dbh->prepare($sql);
                    $stmt->bindParam(":passwordresetid", $passwordresetid);
                    $stmt->bindParam(":userid", $userid);
                    $stmt->bindParam(":email", $email);
                    $result = $stmt->execute();

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


                } else {

                    $this->auditlog("passwordReset", "Bad request for $usernameOrEmail");

                }

            }

            // Close the connection
            $dbh = NULL;

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

            // Connect to the database
            $dbh = $this->getConnection();

            // Construct a SQL statement to perform the insert operation
            $sql = "SELECT userid FROM passwordreset WHERE passwordresetid = :passwordresetid AND expires > NOW()";

            // Run the SQL select and capture the result code
            $stmt = $dbh->prepare($sql);
            $stmt->bindParam(":passwordresetid", $passwordresetid);
            $result = $stmt->execute();

            // If the query did not run successfully, add an error message to the list
            if ($result === FALSE) {

                $errors[] = "An unexpected error occurred updating your password.";
                $this->auditlog("updatePassword", $stmt->errorInfo());
                $this->debug($stmt->errorInfo());

            } else if ($stmt->rowCount() == 1) {

                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                $userid = $row['userid'];
                $this->updateUserPassword($userid, $password, $errors);
                $this->clearPasswordResetRecords($passwordresetid);

            } else {

                $this->auditlog("updatePassword", "Bad request id: $passwordresetid");

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

        // Connect to the database
        $dbh = $this->getConnection();

        // Construct a SQL statement to perform the select operation
        $sql = "SELECT attachmenttypeid, name, extension FROM attachmenttypes ORDER BY name";

        // Run the SQL select and capture the result code
        $stmt = $dbh->prepare($sql);
        $result = $stmt->execute();

        // If the query did not run successfully, add an error message to the list
        if ($result === FALSE) {

            $errors[] = "An unexpected error occurred getting the attachment types list.";
            $this->debug($stmt->errorInfo());
            $this->auditlog("getattachmenttypes error", $stmt->errorInfo());

            // If the query ran successfully, then get the list of users
        } else {

            // Get all the rows
            $types = $stmt->fetchAll();
            $this->auditlog("getattachmenttypes", "success");

        }

        // Close the connection
        $dbh = NULL;

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

            // Connect to the database
            $dbh = $this->getConnection();

            // Construct a SQL statement to perform the insert operation
            $sql = "INSERT INTO attachmenttypes (attachmenttypeid, name, extension) VALUES (:attachmenttypeid, :name, :extension)";

            // Run the SQL select and capture the result code
            $stmt = $dbh->prepare($sql);
            $stmt->bindParam(":attachmenttypeid", $attachmenttypeid);
            $stmt->bindParam(":name", $name);
            $stmt->bindParam(":extension", strtolower($extension));
            $result = $stmt->execute();

            // If the query did not run successfully, add an error message to the list
            if ($result === FALSE) {

                $errors[] = "An unexpected error occurred";
                $this->debug($stmt->errorInfo());
                $this->auditlog("newAttachmentType error", $stmt->errorInfo());
                return NULL;

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
      return $stmt->rowCount();
    }
}


?>
