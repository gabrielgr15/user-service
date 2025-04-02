const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const jwt = require('jsonwebtoken')
const RefreshToken = require('../models/RefreshToken')
const {verifyTokenAndCheckBlackList, generateTokens} = require('../utils/tokenUtils')
const auth = require('../middleware/auth')
const redisClient = require('../redis/redisClient')
const logger = require('../logger')

const router = express.Router();

router.post(
  '/register',
  [
    body('username', 'Username is required').notEmpty().trim(),
    body('email', 'Please include a valid email').isEmail().normalizeEmail(),
    body('password', 'Password is required').notEmpty().isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
      let user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ error: 'User already exists'  });
}
      user = new User({
        username,
        email,
        password
})
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);

        await user.save();
	const { accessToken, refreshToken } = await generateTokens(user)
	return res.status(201).json({accessToken, refreshToken })
}	catch (err) {
		logger.error(err);
    	res.status(500).send('Server error');
}
})



router.post(
	'/login',
	[
	body('email', 'The email is incorrect').notEmpty().isEmail().normalizeEmail(),
	body('password', 'The password is incorrect').notEmpty(),
	],
	async (req, res) => {
	const errors = validationResult(req)
	if(!errors.isEmpty()){
		return res.status(400).json({ errors : errors.array() })
}
	const  { email, password } = req.body;

	try{
		const cacheKey = `user:login:cache:${email}`

		const cachedUserData = await redisClient.get(cacheKey)
		let user = null 
		if (cachedUserData) {
			user = JSON.parse(cachedUserData)			
		}	else {
				user = await User.findOne({email}).select('+password')
				
		if (!user){
			return res.status(400).send('This email does not  exist')
		}}	
		
		if (!user.password){
			logger.error('User password is missing:,', user)
			return res.status(500).json({error: 'Invalid user data'})
		}

		const userIdForToken = user._id ? user._id : user.userId

		if (!cachedUserData && user._id) {
			const userDataToCache = {
				userId : user._id.toString(),
				name : user.username,
				email : user.email,
				password: user.password
					}
				
			await redisClient.set(cacheKey, JSON.stringify(userDataToCache),'EX',300)
		}	
				
		const isMatch = await bcrypt.compare(password, user.password)
		if (!isMatch){
			return res.status(400).json({errors : [{ msg : 'Incorrect password'}] })
			}
		const { accessToken, refreshToken } = await generateTokens(userIdForToken)
		return res.status(200).json({accessToken, refreshToken});			
}	catch (err){
		logger.error(err)
		return res.status(500).json({error: 'Internal server error', err})		
}})


router.post(
	'/refresh',
	auth,
	[
	body('token', 'Refresh token is required').trim().notEmpty().isString(),
	],
	async (req, res) => {
	const errors = validationResult(req)
	if (!errors.isEmpty()){
	res.status(400).json({error: errors.array })
}	try{
	const {token} = req.body
	storedToken = await RefreshToken.findOne({token})
	if (!storedToken || storedToken.token !== token){
	res.status(404).json({error : 'Invalid token'})
}	const user = storedToken.user
	await RefreshToken.findByIdAndDelete(storedToken-_id)
	const {refreshToken, accessToken} = await generateTokens(user)
	res.status(200).json({refreshToken, accessToken})
}	catch(err){
	res.status(500).json({error : 'Internal server error', err})
}})

router.post(
	'/verify',
	[
	body('token','Requires a token').trim().notEmpty()
	],
	async (req, res) => {
	const errors = validationResult(req)
	if (!errors.isEmpty()){
	return res.status(400).json({errors : errors.array() })
}	try{
	const {token} = req.body
	const payload = await verifyTokenAndCheckBlackList(token)
	const user = payload.user
	return res.status(200).json({userId : user.id  })
}	catch (err){
	logger.error(err)
	return res.status(401).json({error: 'Invalid token', })
}})


router.post(
	'/logout',
	auth,
	async (req,res) => {
		const authHeader = req.header('Authorization')
		const token = authHeader.split(' ')[1]		
		try{
			const decoded = jwt.decode(token)
			if (!decoded || !decoded.exp){
				return res.status(400).json({error : 'Cannot decode token or find exp claim'})
			}
			const tokenId = decoded.jti || token
			const expirationTimestamp = decoded.exp
			const nowInSeconds = Math.floor(Date.now()/1000)
			const ttlSeconds = expirationTimestamp - nowInSeconds

			if (ttlSeconds > 0){
				const redisKey = `blacklist:${tokenId}`
				const value = 1

				await redisClient.set(redisKey, 1, {EX : ttlSeconds})

				return res.status(204).send()
		}
		}catch (err){
			return res.status(500).json({error: 'Internal server error during logout'})
				}
		}
)


module.exports = router;
