const redis = require('redis');

const redisClient = redis.createClient({
    url: 'redis://localhost:6379' 
});

(async () => {
    try {
        redisClient.on('error', (err) => console.error('Redis Client Error:', err));
        await redisClient.connect();
        console.log('Connected to Redis successfully!');
    } catch (error) {
        console.error('Failed to connect to Redis:', error);
    }
})();

module.exports = redisClient;