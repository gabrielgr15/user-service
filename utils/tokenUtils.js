const RefreshToken = require('../models/RefreshToken')
const crypto = require('crypto')
const config = require('config')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const redisClient = require('../redis/redisClient')
const logger = require('../logger')

async function generateTokens(userId){
try{
	const user = await User.findById(userId)
	const payload = {
                user:{
                id: user.id
}}
	const accessToken = await new Promise((resolve, reject) =>{
        jwt.sign(
        payload,
        config.get('jwtSecret'),
        {expiresIn: '1h'},
        (err, token) => {
        if (err){
	reject(err)
}
	resolve(token)
})})
	const newToken = crypto.randomBytes(64).toString('hex')

        const refreshTokenLifespanDays = 7;
        const refreshTokenLifespanMilliseconds = refreshTokenLifespanDays * 24 * 60 * 60 * 1000;
        const refreshTokenExpiresAt = new Date(Date.now() + refreshTokenLifespanMilliseconds);

        let refreshToken = new RefreshToken ({
        token : newToken,
        user : user,
        expiresAt : refreshTokenExpiresAt,
})
	
        await refreshToken.save()
	.catch(err => {
	logger.error('Error saving RefreshToken', err)
	throw err
})
	return {accessToken, refreshToken : refreshToken.token}

}	catch(err){
	logger.error('Error generating tokens: ', err)
	throw err
}}

async function verifyTokenAndCheckBlackList(token){
        try{
                logger.info("DEBUG: Pinging redis before verify... ")
                const pingResult = await redisClient.ping()
                logger.info("DEBUG: Redis ping result:", pingResult)
                  
        const decoded = jwt.verify(token, config.get('jwtSecret'))
        const tokenId = decoded.jti || token
        const redisKey = `blacklist:${tokenId}`
        const check = await redisClient.exists(redisKey)
        if (check === 0) {
                return decoded
        }else{
                logger.info('Token blacklisted')
                throw new Error('Token has been logged out')
        }
        }catch(error) {
                logger.error('<<<<<<<<<<<<<<<<<<< CAUGHT ERROR HERE >>>>>>>>>>>>>>>>>:', error); 
                throw new Error('Invalid token1');
            }
              
}

module.exports = {verifyTokenAndCheckBlackList, generateTokens}
