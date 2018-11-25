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
				conn.end();
			} else {
				console.log("Connected!");
				var sql = "SELECT isadmin FROM users WHERE userid = ? ";
			
				conn.query(sql, [event.userid], function (err, result) {
				  	if (err) {
						// This should be a "Internal Server Error" error
						
						callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
						setTimeout(function() {conn.end();}, 3000);
				  	} else {
			  			console.log("query successful");
			  			if(result[0] === undefined || result[0].length == 0){
			  				
							callback(null, 0);
							setTimeout(function() {conn.end();}, 3000);
			  			} else {
			  				
			  				callback(null, result);
			  				setTimeout(function() {conn.end();}, 3000);
			  			}
					} //valid username
			  	}); //query username
			}
		}); //connect database
	} //no validation errors
}; //handler