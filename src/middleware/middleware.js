import jwt from "jsonwebtoken";
import config from "../config.js";
import pool from "../db/database.js";

export const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];// Se espera formato "Bearer token"
    if (!token) return res.status(401).json({ message: "Acceso denegado" });

    jwt.verify(token, config.jwtSecret, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Token no valido" });
        req.user = decoded;
        next();
    })
};

export const isAdmin = async (req, res, next) => {
    try {
        const result = await pool.query("SELECT role_id FROM roles WHERE role_name = 'Administrator'");
        const adminRoleId = result.rows[0]?.role_id;

        if (req.user.role_id !== adminRoleId) {
            return res.status(403).json({ message: "Acceso denegado" });
        }
        next();
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
