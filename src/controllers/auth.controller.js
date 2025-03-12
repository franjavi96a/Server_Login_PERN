import pool from "../db/database.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import config from "../config.js";


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

//Metodo para loguear un usuario usando JWT
const loginUser = async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: "Todos los campos son obligatorios" })
        }

        const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ message: "Usuario incorrecto" })
        }

        const user = result.rows[0];
        //Compara la contraseña ingresada con la encriptada en la BD
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: "La contraseña es incorrecta" });
        }

        //Generar el token con JWT
        const token = jwt.sign(
            {
                user_id: user.user_id,
                username: user.username,
                role_id: user.role_id,
            },
            config.jwtSecret,
            { expiresIn: "1h" }
        );
        res.status(200).send({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

//Metodo para cambiar la contraseña de un usuario
const changePassword = async (req, res) => {
    try {
        const { user_id } = req.user; // id obtenido del middleware JWT
        const { newPassword } = req.body;

        //Validar que todos los campos sean obligatorios
        if (!newPassword) {
            return res.status(400).json({ error: "Todos los campos son obligatorios" });
        }

        //Encriptar la nueva contraseña
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        const result = await pool.query("UPDATE users SET password = $1 WHERE user_id = $2 RETURNING *", [hashedPassword, user_id]);
        res.status(200).json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

//Exportar todos los metodos
export const methods = {
    registerUsuer,
    loginUser,
    changePassword
}