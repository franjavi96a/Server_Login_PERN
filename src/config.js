import { config } from 'dotenv';

config();

export default {
    port: process.env.PORT || 5000,
    db:{
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_DATABASE,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
    },
    jwtSecret: process.env.JWT_SECRET
}