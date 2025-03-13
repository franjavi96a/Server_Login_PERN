import pool from "../db/database.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import config from "../config.js";
import nodemailer from "nodemailer"; //Para enviar el correo de recuperación de contraseña


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

// Configurar Nodemailer
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: config.email.user,
        pass: config.email.pass // Asegúrate de usar una contraseña de aplicación
    }
});


//Metodo para recuperar las constrasñas de los usuarios
const recoverPassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: "Ingrese el email" });
        }

        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ message: "El email no existe" });
        }
        const user = result.rows[0];
        // Generar un token de recuperación de 6 digitos
        const token = crypto.randomInt(100000, 1000000);

        // Guardar el token en la BD, junto con una fecha de expiración (por ejemplo, 1 hora)
        await pool.query("UPDATE users SET reset_token = $1, reset_expires = NOW() + INTERVAL '5 minutes' WHERE email = $2", [token, email]);

        // Configurar el correo a enviar
        const mailOptions = {
            from: '"Soporte" <${config.email.user}>', // Debe ser un correo verificado en tu proveedor SMTP
            to: email,
            subject: 'Recuperación de contraseña',
            html: `<p>Hola <strong>${user.username}</strong>,</p>
                    <p>Para recuperar tu contraseña, utiliza el siguiente codigo:</p>
                    <p><strong>${token}</strong></p>
                    <p>Si no solicitaste este cambio, ignora este correo.</p>`
        };

        // Enviar el correo
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ error: "Error al enviar el correo de recuperación" });
            }
            res.json({ message: "Correo de recuperación enviado correctamente" });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}

//Exportar todos los metodos
export const methods = {
    registerUsuer,
    loginUser,
    changePassword,
    recoverPassword
}