var mysql = require('./node_modules/mysql');
var config = require('./config.json');

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
	if(errors.length > 0) {
		// This should be a "Bad Request" error
		console.log("BAD REQUEST");
		callback(formatErrorResponse('BAD_REQUEST', errors));
	} else {
		//getConnection equivalent
			var conn = mysql.createConnection({
				host 	: config.dbhost,
				user 	: config.dbuser,
				password : config.dbpassword,
				database : config.dbname
			});
		
	
		//prevent timeout from waiting event loop
		context.callbackWaitsForEmptyEventLoop = false;
		//attempts to connect to the database
		conn.connect(function(err) {
			if (err)  {
				// This should be a "Internal Server Error" error
		  		
				callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
				setTimeout(function() {conn.end();}, 3000)
			} else {
				console.log("Connected!");
				var sql = "SELECT email, userid FROM users WHERE username = ? OR email = ?";
			
				conn.query(sql, [event.usernameOrEmail, event.usernameOrEmail], function (err, result) {
				  	if (err) {
						// This should be a "Internal Server Error" error
			  			
						callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
						setTimeout(function() {conn.end();}, 3000);
				  	} else if(result.length != 1){
			  			console.log("email or username not found or more than one result returned. exiting...");
			  			errors.push("email or username not found");
			  			
						callback(formatErrorResponse('BAD_REQUEST', errors));
						setTimeout(function() {conn.end();}, 3000);
					} else {
						console.log("username/email found!");
						var userid = result[0].userid;
						var email = result[0].email;
						sql = "INSERT INTO passwordreset (passwordresetid, userid, email, expires) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))";
						conn.query(sql, [event.passwordresetid, userid, email], function (err, result) {
							if (err) {
								// This should be a "Internal Server Error" error
								callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
								setTimeout(function() {conn.end();}, 3000);
				  			} else if(result.affectedRows != 1){
			  					console.log("Could not delete validation id");
			  					errors.push("There was an error validating your email");
			  					
								callback(formatErrorResponse('BAD_REQUEST', errors));
								setTimeout(function() {conn.end();}, 3000);
							} else {
								console.log("password reset id inserted");
								callback(null, email);
								setTimeout(function() {conn.end();}, 3000);
							}
						});
					}//valid username
			  	}); //query username
			}
		}); //connect database
	} //no validation errors
}; //handler