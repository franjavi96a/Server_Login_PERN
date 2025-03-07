import  config from "../config.js";
import pg from "pg";
const {Pool} = pg;

const pool = new Pool({
    user: config.db.user,
    host: config.db.host,
    database: config.db.database,
    password: config.db.password,
    port: config.db.port
});

export default pool;