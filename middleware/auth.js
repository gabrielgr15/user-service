const { verifyTokenAndCheckBlackList } = require('../utils/tokenUtils')
const { AuthError, CustomError, ServerError } = require('../errors')
const logger = require('../logger')

module.exports = async function (req, res, next) {
	const authHeader = req.header('Authorization')
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		throw new AuthError('No authorization token, access denied')
	}
	try {
		const token = authHeader.split(' ')[1]
		if (!token) throw new AuthError('Token missing from header')
		const decoded = await verifyTokenAndCheckBlackList(token)
		req.user = decoded.user
		req.token = decoded.jti
		req.tokenExpiry = decoded.exp
		next();
	} catch (error) {
		if(error instanceof CustomError){
			throw error
		}
		throw new ServerError('An internal server error occurred', {cause: error})
	}	
}