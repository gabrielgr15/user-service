const jwt = require('jsonwebtoken')
const logger = require('../logger')
const config = require('config')
const util = require('util')
const { ServerError } = require('../errors')
const crypto = require('crypto')
const RefreshToken = require('../models/RefreshToken')

const signPromise = util.promisify(jwt.sign)


async function generateAccessToken(userId) {
    if (!userId) {
        logger.error('Invalid argument passed to generateAccessToken', {userId})
        throw new ServerError('Invalid argument to generate access token')
    }
    const secret = config.get('jwtSecret')
    if (!secret) {
        logger.error('JWT secret is not configured')
        throw new Error('JWT secret is not configured')
    }
    try {
        const payload = {
            user: {
                id: userId.toString(),
            },
            jti: crypto.randomBytes(16).toString('hex')
        }
        const options = {
            expiresIn: '1h'
        }
        const accessToken = await signPromise(payload, secret, options)
        return accessToken
    } catch (error) {        
        throw new ServerError('An internal server error occurred', {cause: error}) 
    }
}

async function generateRefreshToken(user) {
    if (!user) {
        logger.error('Invalid argument passed to generateRefreshToken', {userId: user._id})
        throw new ServerError('Invalid argument to generate refresh token')
    }
    try {
        const newToken = crypto.randomBytes(64).toString('hex')
        const refreshTokenLifespanDays = config.get('jwtRefreshExpiresInDays') || 7
        const refreshTokenLifespanMilliseconds = refreshTokenLifespanDays * 24 * 60 * 60 * 1000;
        const refreshTokenExpiresAt = new Date(Date.now() + refreshTokenLifespanMilliseconds);

        let refreshToken = new RefreshToken({
            token: newToken,
            user: user,
            expiresAt: refreshTokenExpiresAt,
        })
        return refreshToken
    } catch (error) {
        throw new ServerError('An internal server error occurred', {cause: error}) 
    }
}

module.exports = { generateAccessToken, generateRefreshToken }