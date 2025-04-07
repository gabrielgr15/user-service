const config = require('config')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const redisClient = require('../redis/redisClient')
const logger = require('../logger')
const { generateAccessToken, generateRefreshToken } = require('./authHelpers')
const { ServerError, CustomError, AuthError } = require('../errors')

async function generateTokens(userId) {
    if (!userId) {
        logger.error('Invalid arguments passed to generateTokens', {userId})
        throw new ServerError('Invalid argument for tokens generation')
    }
    try {        
        const user = await User.findOne({ _id: userId })       
        if (!user) {
            logger.error('User record not found for token generation', {userId})
            throw new ServerError('User record not found for token generation')
        }
        const accessToken = await generateAccessToken(userId)
        const refreshToken = await generateRefreshToken(user)
        await refreshToken.save()        
        return { accessToken, refreshToken: refreshToken.token }
    } catch (error) {
        if (error instanceof CustomError) {
            throw error
        }
        throw new ServerError('An internal server error occurred', {cause: error})
    }
}


async function verifyTokenAndCheckBlacklist(token) {
    if(!token) {
        logger.error('Invalid arguments passed to verifyTokenAndCheckBlacklist', {token})
        throw new ServerError('invalid argument for token verification')
    }
    try {
        const decoded = jwt.verify(token, config.get('jwtSecret'));
        // Check jti presence since blacklist relies on it, data integrity matters.
        if (!decoded.jti) {
            logger.warn('Token missing jti', { token });
            throw new AuthError('Invalid token structure');
        }
        // Could split blacklist check for modularity, but kept cohesive here.
        const isBlacklisted = await redisClient.exists(`blacklist:${decoded.jti}`);
        if (isBlacklisted) throw new AuthError('Token is blacklisted');
        return decoded;
    } catch (error) {
        // Map JWT failures to AuthError for semantic clarity.
        if (error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError) {
            throw new AuthError('Invalid token');
        }
        if (error instanceof CustomError) {
            throw error
        }        
        throw new ServerError('An internal server error occurred', {cause: error}) 
    }
}

function generateBlacklistData(tokenId, expirationTimestamp) {
    if(!tokenId || typeof expirationTimestamp !== 'number'){
        logger.error('Invalid arguments passed to generateBlacklistData', {tokenId, expirationTimestamp})
        throw new ServerError('Invalid arguments for blacklist data generation')
    }
    const nowInSeconds = Math.floor(Date.now() / 1000)
    const ttlSeconds = expirationTimestamp - nowInSeconds
    const redisKey = `blacklist:${tokenId}`
    const value = 1
    return { redisKey, value, ttlSeconds }
}

module.exports = { verifyTokenAndCheckBlacklist, generateTokens, generateBlacklistData }
