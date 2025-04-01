const RefreshToken = require('../models/RefreshToken')
const crypto = require('crypto')
const config = require('config')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const redisClient = require('../redis/redisClient')

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
	console.log('refreshToken object:', refreshToken)
        await refreshToken.save()
	.then(savedToken => {
	console.log('RefreshToken saved succesfully:', savedToken)
})
	.catch(err => {
	console.error('Error saving RefreshToken', err)
	throw err
})
	return {accessToken, refreshToken : refreshToken.token}
}	catch(err){
	console.error('Error generating tokens: ', err)
	console.error('Full error object:', err)
	throw err
}}

async function verifyTokenAndCheckBlackList(token){
        try{
                console.log("DEBUG: Pinging redis before verify... ")
                const pingResult = await redisClient.ping()
                console.log("DEBUG: Redis ping result:", pingResult)
                console.log("DEBUG: Token being passed to jwt.verify:", token)   
        const decoded = jwt.verify(token, config.get('jwtSecret'))
        const tokenId = decoded.jti || token
        const redisKey = `blacklist:${tokenId}`
        const check = await redisClient.exists(redisKey)
        if (check === 0) {
                return decoded
        }else{
                console.error('Token blacklisted')
                throw new Error('Token has been logged out')
        }
        }catch(error) {
                console.error('<<<<<<<<<<<<<<<<<<< CAUGHT ERROR HERE >>>>>>>>>>>>>>>>>:', error); // Make it super visible
                throw new Error('Invalid token1');
            }
              
}

module.exports = {verifyTokenAndCheckBlackList, generateTokens}
