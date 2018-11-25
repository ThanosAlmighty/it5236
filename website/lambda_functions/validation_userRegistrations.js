exports.validateUserID = function(userid, errors){
	if (!userid) {
        errors.push("Missing user ID");
	} 
}