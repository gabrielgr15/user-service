const redis = require('redis');
const logger = require('../logger')

const redisClient = redis.createClient({
    url: 'redis://localhost:6379' 
});

(async () => {
    try {
        redisClient.on('error', (err) => logger.error('Redis Client Error:', err));
        await redisClient.connect();
        logger.info('Connected to Redis successfully!');
    } catch (error) {
        logger.error('Failed to connect to Redis:', error);
    }
})();

module.exports = redisClient;