const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken')
const { generateTokens, generateBlacklistData } = require('../utils/tokenUtils')
const auth = require('../middleware/auth')
const redisClient = require('../redis/redisClient')
const logger = require('../logger')
const { AuthError, ServerError, ValidationError, ConflictError, CustomError } = require('../errors')

const router = express.Router();

router.post(
	'/register',
	[
		body('username', 'Username is required').notEmpty().trim(),
		body('email', 'Please include a valid email').isEmail().normalizeEmail(),
		body('password', 'Password must be 6+ characters').isLength({ min: 6 }),
	],
	async (req, res, next) => {		
		const errors = validationResult(req)
		if (!errors.isEmpty()) {
			return next(new ValidationError('Invalid input', errors.array()))
		}
		const { username, email, password } = req.body
		try {
			const existingUser = await User.findOne({ email });
			if (existingUser) throw new ConflictError('Email already registered');

			const user = new User({ username, email });
			user.password = await bcrypt.hash(password, 10);
			await user.save();

			const { accessToken, refreshToken } = await generateTokens(user._id);
			return res.status(201).json({ accessToken, refreshToken });
		} catch (error) {
			if (error instanceof CustomError) {
				next(error)
			} else {
				next(new ServerError('An internal server error occurred', { cause: error }))
			}

		}
	}
);


router.post(	
	'/login',
	[		
		body('email', 'The email is incorrect').notEmpty().isEmail().normalizeEmail(),
		body('password', 'The password is incorrect').notEmpty(),		
	],	
	async (req, res, next) => {		
		const errors = validationResult(req)
		if (!errors.isEmpty()) {
			return next(new ValidationError('Invalid credentials', errors.array()))
		}		
		const { email, password } = req.body		
		try {
			const user = await User.findOne({ email }).select('+password')

			if (!user) throw new AuthError('Invalid credentials')
			if (!user.password) throw new ServerError('User data incomplete in database')

			const isMatch = await bcrypt.compare(password, user.password)
			if (!isMatch) throw new AuthError('Incorrect password')

			const userId = user._id
			const { accessToken, refreshToken } = await generateTokens(userId)
			return res.status(200).json({ accessToken, refreshToken });
		} catch (error) {
			if (error instanceof CustomError) {
				next(error)
			} else {
				next(new ServerError('An internal server error occurred', { cause: error }))
			}
		}
	})


router.post(
	'/refresh',
	[
		body('token', 'Refresh token is required').trim().notEmpty().isString(),
	],
	async (req, res, next) => {
		const errors = validationResult(req)
		if (!errors.isEmpty()) {
			return next(new ValidationError('Invalid credentials', errors.array()))
		}
		try {
			const { token } = req.body
			const storedToken = await RefreshToken.findOne({ token })
			if (!storedToken) throw new AuthError('Invalid refresh token')
			if (storedToken.expiresAt < new Date()) throw new AuthError('Refresh token expired')

			const user = storedToken.user
			if (!user || !user._id) throw new ServerError('Error reading user data from refresh token')

			await RefreshToken.findByIdAndDelete(storedToken._id)

			const userId = user._id
			const { refreshToken, accessToken } = await generateTokens(userId)
			return res.status(200).json({ accessToken, refreshToken })
		} catch (error) {
			if (error instanceof CustomError) {
				next(error)
			} else {
				next(new ServerError('An internal server error occurred', { cause: error }))
			}
		}
	})


router.post(
	'/logout',	
	async (req, res, next) => {
		const headers = req.headers
		const tokenId = headers['x-token-id']
		const expiryHeader = headers['x-token-expiry']
		const expirationTimestamp = parseInt(expiryHeader, 10)
		try {			
			const { redisKey, value, ttlSeconds } = generateBlacklistData(tokenId, expirationTimestamp)

			if (ttlSeconds <= 0) {
				logger.warn('Logout requested for already expired token')
				return res.status(204).send()
			}
			await redisClient.set(redisKey, value, { EX: ttlSeconds })

			return res.status(204).send()
		} catch (error) {
			if (error instanceof CustomError) {
				next(error)
			}else{
				next(new ServerError('An internal server error occurred', { cause: error }))
			}			
		}
	}
)

module.exports = router;
