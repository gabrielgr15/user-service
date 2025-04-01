const {verifyTokenAndCheckBlackList} = require('../utils/tokenUtils')

module.exports = async function(req, res, next){

	if (req.path === '/refresh' || req.path === '/refresh/'){
		return next()
}
	const authHeader = req.header('Authorization');
	
	if (!authHeader){
		return res.status(401).json({msg: 'No token, authorization denied'})
}
	try{
		const token = authHeader.split(' ')[1]
		const payload = await verifyTokenAndCheckBlackList(token)
		req.user = payload.user;
		next(); 
}	catch (err){
		console.error(err)
		res.status(401).json({msg: 'Token is not valid'})
}}