const config = require('config')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const redisClient = require('../redis/redisClient')
const logger = require('../logger')
const { generateAccessToken, generateRefreshToken } = require('./authHelpers')
const { ServerError, CustomError, AuthError } = require('../errors')
const {redisCheckBreaker} = require('./circuitBreaker')

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
        }else{
            throw new ServerError('An internal server error occurred', {cause: error})
        }        
    }
}


function generateBlacklistData(expirationTimestamp) {
    if(typeof expirationTimestamp !== 'number' || isNaN(expirationTimestamp)){
        logger.error('Invalid arguments passed to generateBlacklistData', {expirationTimestamp})
        throw new ServerError('Invalid arguments for blacklist data generation')
    }
    const nowInSeconds = Math.floor(Date.now() / 1000)
    const ttlSeconds = expirationTimestamp - nowInSeconds   
    return {ttlSeconds}
}

module.exports = { verifyTokenAndCheckBlacklist, generateTokens, generateBlacklistData }
