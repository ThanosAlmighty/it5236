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
			var sql = "SELECT commentid, commenttext, convert_tz(comments.commentposted,@@session.time_zone,'America/New_York') as commentposted, username, attachmentid, filename FROM comments LEFT JOIN users ON comments.commentuserid = users.userid LEFT JOIN attachments ON comments.commentattachmentid = attachments.attachmentid WHERE commentthingid = ? ORDER BY commentposted ASC";
		
			conn.query(sql, [event.thingid], function (err, result) {
			  	if (err) {
					// This should be a "Internal Server Error" error
					
					callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
					setTimeout(function() {conn.end();}, 3000);
			  	} else {
		  			console.log("query successful");
		  			
					callback(null, result);
					setTimeout(function() {conn.end();}, 3000);
				} //valid username
		  	}); //query username
		}); //connect database
	} //no validation errors
}; //handler