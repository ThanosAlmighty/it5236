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
			};
			console.log("Connected!");
			var sql = "INSERT INTO OTP (otp, sessionid, date) VALUES (?, ?, NOW());";
		
			conn.query(sql, [event.otp, event.sessionid], function (err, result) {
			  	if (err) {
					// This should be a "Internal Server Error" error
					
					callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
					setTimeout(function() {conn.end();}, 3000);
			  	} else {
		  			console.log("query successful");
		  			
					callback(null, result.affectedRows);
					setTimeout(function() {conn.end();}, 3000);
				} //valid username
		  	}); //query username
		}); //connect database
	} //no validation errors
}; //handler