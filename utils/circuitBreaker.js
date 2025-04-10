const CircuitBreaker = require('opossum')
const redisClient = require('../redis/redisClient')
const logger = require('../logger')

logger.info('Circuit breaker configuration module loaded')



const addToBlacklistAction = async (token, expiryInSeconds) => {
    const redisKey = `blacklist:${token}`
    const value = 1
    try {
        const result = await redisClient.set(redisKey, value, { EX: expiryInSeconds, NX: true })
        if (result === 'OK') {
            logger.info(`[addToBlacklistAction] Successfully added token to Redis blacklist (NX): ${redisKey}`);
        } else if (result === null) {            
            logger.info(`[addToBlacklistAction] Token already in Redis blacklist (NX prevented set): ${redisKey}`)            
        } else {            
            logger.warn(`[addToBlacklistAction] Redis SETEX NX returned unexpected result: ${result} for key ${redisKey}`);
        }
        return result
    } catch (error) {
        logger.error(`[addToBlacklistAction] Redis SETEX failed for key ${redisKey}:`, error)
        throw error
    }
}


const fallbackSkipRedis = (token, expiryInSeconds, error) => {
    logger.warn(`[${redisBlacklistOptions.name}] Fallback triggered.
        Skipping Redis blacklist add. Token (start): ${token?.substring(0, 8)}...
        Reason: ${error ? error.message : 'Circuit Open'}`)
    return 'FALLBACK_SKIPPED_REDIS'
}


const redisAddOptions = {
    rollingCountTimeout: 10000,
    volumeThreshold: 3,
    errorThresholdPercentage: 50,
    timeout: 3000,
    resetTimeout: 20000,
    name: 'RedisLogoutBlacklist',    
}


const redisAddBreaker = new CircuitBreaker(addToBlacklistAction, redisAddOptions)


redisAddBreaker.fallback(fallbackSkipRedis)




logger.info(`Circuit breaker "${redisAddBreaker.name}" initialized`)



redisAddBreaker.on('open', () => {    
    logger.error(`[${redisAddBreaker.name}] Circuit OPENED. Failing fast and using fallback.`);
});


redisAddBreaker.on('close', () => {    
    logger.info(`[${redisAddBreaker.name}] Circuit CLOSED. Redis calls have resumed.`);
});


redisAddBreaker.on('halfOpen', () => {    
    logger.warn(`[${redisAddBreaker.name}] Circuit HALF-OPEN. Attempting next Redis call to test health.`);
});


redisAddBreaker.on('fallback', (result, error) => {    
    logger.warn({
        message: `[${redisAddBreaker.name}] Fallback executed.`,
        fallbackResult: result,
        triggeringError: error ? error.message : 'N/A (Circuit was open)',        
    });
});


redisAddBreaker.on('success', (result) => {    
    logger.debug({
        message: `[${redisAddBreaker.name}] Action successful.`,
        actionResult: result,        
    });
});


redisAddBreaker.on('failure', (error) => {    
    logger.error({
        message: `[${redisAddBreaker.name}] Action failed.`,
        error: error ? error.message : 'Unknown Error',        
    });
})



logger.info(`Event listeners attached to circuit breaker "${redisAddBreaker.name}".`);



module.exports = {
    redisAddBreaker,    
}

