import redis from "redis";

const redisConnect = async () => {

    const redisClient = await redis.createClient({
        url: process.env.REDIS_URL
    })
    .on('error', (err) => {
        console.log('Redis Client Error', err);
    })
    .on('connect', () => {
        console.log('Connected to Redis Client')
    }).connect();

    return redisClient;
}

export default redisConnect; 