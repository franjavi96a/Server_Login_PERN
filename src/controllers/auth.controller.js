import pool from "../db/database.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const saltRounds = 10;

// Registrar un nuevo usuario (este endpoint lo podrán usar el admin para crear usuarios con roles específicos)
const registerUsuer = async (req, res) => {
    try {
        const { username, email, password, role_id } = req.body;

        //Validar que todos los campos sean obligatorios
        if (!username || !email || !password || !role_id) {
            return res.status(400).json({ error: "Todos los campos son obligatorios" });
        }

        const user_id = crypto.randomUUID();
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const result = await pool.query(`INSERT INTO users (user_id, username, password, email, role_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) RETURNING *`, [user_id, username, hashedPassword, email, role_id]);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

//Exportar todos los metodos
export const methods = {
    registerUsuer
}