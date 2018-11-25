var mysql = require('./node_modules/mysql');
var config = require('./config.json');
var validator = require('./validation.js');

function formatErrorResponse(code, errs) {
	return JSON.stringify({ 
		error  : code,
		errors : errs
	});
}

exports.handler = (event, context, callback) => {
	
	context.callbackWaitsForEmptyEventLoop = false;
	//validate input
	var errors = new Array();
	
	 // Validate the user input
	validator.validateUsername(event.username, errors);
	validator.validatePasswordHash(event.passwordHash, errors);
	validator.validateEmail(event.email, errors);
	validator.validateRegistrationCode(event.registrationcode, errors);
	validator.validateuserid(event.userid, errors);
	
	if(errors.length > 0) {
		// This should be a "Bad Request" error
		callback(formatErrorResponse('BAD_REQUEST', errors));
	} else {
	
	//getConnection equivalent
		if(conn === undefined){
				var conn = mysql.createConnection({
					host 	: config.dbhost,
					user 	: config.dbuser,
					password : config.dbpassword,
					database : config.dbname
				});
			}
		//prevent timeout from waiting event loop
		context.callbackWaitsForEmptyEventLoop = false;
	
		//attempts to connect to the database
		conn.connect(function(err) {
		  	
			if (err)  {
				// This should be a "Internal Server Error" error
				
				callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
				setTimeout(function() {conn.end();}, 3000);
			} else {
				console.log("Connected!");
				var sql = "SELECT COUNT(*) AS codecount FROM registrationcodes WHERE LOWER(registrationcode) = LOWER(?)  ";
				
				conn.query(sql, [event.registrationcode], function (err, result) {
				  	if (err) {
						// This should be a "Internal Server Error" error
						
						callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
						setTimeout(function() {conn.end();}, 3000);
				  	} else {
				    	console.log("Registration code count is " + result[0].codecount);
				    	if (result[0].codecount == 0){
				    		errors.push("Bad registration code");
				    		
							callback(formatErrorResponse('BAD_REQUEST', errors));
							setTimeout(function() {conn.end();}, 3000);
				    	} else {
							var sql = "INSERT INTO users (userid, username, passwordhash, email) " +
				                "VALUES (?, ?, ?, ?)";
							conn.query(sql, [event.userid, event.username, event.passwordHash, event.email], function (err, result) {
								if (err) {
									// Check for duplicate values
									if(err.errno == 1062) {
										console.log(err.sqlMessage);
										if(err.sqlMessage.indexOf('username') != -1) {
											// This should be a "Internal Server Error" error
											
											callback(formatErrorResponse('BAD_REQUEST', ["Username already exists"]));
											setTimeout(function() {conn.end();}, 3000);
										} else if(err.sqlMessage.indexOf('email') != -1) {
											// This should be a "Internal Server Error" error
											
											callback(formatErrorResponse('BAD_REQUEST', ["Email address already registered"]));
											setTimeout(function() {conn.end();}, 3000);
										} else {
											// This should be a "Internal Server Error" error
											
											callback(formatErrorResponse('BAD_REQUEST', ["Duplicate value"]));
											setTimeout(function() {conn.end();}, 3000);
										}
									} else {
										// This should be a "Internal Server Error" error
										
										callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
										setTimeout(function() {conn.end();}, 3000);
									}
					      		} else {
						      		var sql = "INSERT INTO userregistrations (userid, registrationcode) " +
				                    "VALUES (?, ?)";
											conn.query(sql, [event.userid, event.registrationcode], function (err, result) {
										if (err) {
											
							        		callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
							        		setTimeout(function() {conn.end();}, 3000);
							      		} else {
								        	console.log("successful registration");
								        	
							      			callback(null,"user registration successful");
							      			setTimeout(function() {conn.end();}, 3000);
						      			}
				      				}); //query userregistrations
				      			} //error users
			    			}); //query users
			  			} //good registration
					} //good code count
			  	}); //query registration codes
			}
		}); //connect database
	} //no validation errors
} //handler