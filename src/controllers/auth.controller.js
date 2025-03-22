import pool from "../db/database.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import config from "../config.js";
import nodemailer from "nodemailer"; //Para enviar el correo de recuperación de contraseña


const saltRounds = 10;

// Registrar un nuevo usuario (este endpoint lo podrán usar el admin para crear usuarios con roles específicos)
const registerUsuer = async (req, res, next) => {
    try {
        const { username, email, password, role_name } = req.body;

        //Validar que todos los campos sean obligatorios
        if (!username || !email || !password || !role_name) {
            return res.status(400).json({ error: "Todos los campos son obligatorios" });
        }

        // Verificar si el username o email ya existen en la base de datos
        const checkUser = await pool.query(
            "SELECT username, email FROM users WHERE username = $1 OR email = $2", [username, email]);

        if (checkUser.rowCount > 0) {
            if (checkUser.rows.some(user => user.username === username)) {
                return res.status(400).json({ error: "El username ya está en uso." });
            }
            if (checkUser.rows.some(user => user.email === email)) {
                return res.status(400).json({ error: "El email ya está registrado." });
            }
        }

        // Validar el rol ingresado existe
        const role = await pool.query("SELECT role_id FROM roles WHERE role_name = $1", [role_name]);
        if (role.rows.length === 0) {
            return res.status(400).json({ error: "El rol no existe." });
        }
        const role_id = role.rows[0].role_id;

        //Encriptar la contraseña
        const user_id = crypto.randomUUID();
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Usar transacción para mayor seguridad en la inserción
        await pool.query("BEGIN");

        await pool.query(`INSERT INTO users (user_id, username, password, email, role_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) RETURNING *`, [user_id, username, hashedPassword, email, role_id]);

        await pool.query("COMMIT");

        res.status(201).json({ message: 'Usuario creado correctamente' });
    } catch (error) {
        await pool.query("ROLLBACK");
        next(error);
    }
};

//Metodo para loguear un usuario usando JWT
const loginUser = async (req, res, next) => {
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
        next(error);
    }
};

//Metodo para cambiar la contraseña de un usuario
const changePassword = async (req, res, next) => {
    try {
        const { user_id } = req.user; // id obtenido del middleware JWT
        const { newPassword } = req.body;

        //Validar que todos los campos sean obligatorios
        if (!newPassword) {
            return res.status(400).json({ error: "Todos los campos son obligatorios" });
        }

        //Encriptar la nueva contraseña
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        const result = await pool.query("UPDATE users SET password = $1, updated_at = NOW() WHERE user_id = $2 RETURNING *", [hashedPassword, user_id]);
        res.status(200).json({ message: 'Contraseña cambiada correctamente' });
    } catch (error) {
        next(error);
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
const recoverPasswordEmail = async (req, res, next) => {
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

        // Guardar el token en la BD, junto con una fecha de expiración de 5 minutos
        await pool.query("UPDATE users SET reset_token = $1, reset_expires = NOW() + INTERVAL '5 minutes' WHERE email = $2", [token, email]);

        // Configurar el correo a enviar
        const mailOptions = {
            from: '"Soporte" <${config.email.user}>', // Debe ser un correo verificado en tu proveedor SMTP
            to: email,
            subject: 'Recuperación de contraseña',
            html: ` <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; line-height: 1.6;">
                        <p>Hola <strong>${user.username}</strong>,</p>

                        <p>Hemos recibido una solicitud para restablecer tu contraseña.</p>

                        <p>Utiliza el siguiente código para continuar con el proceso:</p>

                        <p style="font-size: 20px; font-weight: bold; color: #007bff; background: #f4f4f4; padding: 10px; display: inline-block; border-radius: 5px;">
                            ${token}
                        </p>

                        <p>Este código es válido por <strong>5 minutos</strong>. Si expira, puedes solicitar uno nuevo.</p>

                        <p>Si no realizaste esta solicitud, puedes ignorar este mensaje. Tu cuenta sigue segura.</p>

                        <p>Atentamente, <br><strong>El equipo de soporte</strong></p>
                    </div>`
        };

        // Enviar el correo
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ error: "Error al enviar el correo de recuperación" });
            }
            res.json({ message: "Correo de recuperación enviado correctamente" });
        });

    } catch (error) {
        next(error);
    }
}

//Metodo para resetear la contraseña por codigo de recuperacion
const resetPassword = async (req, res, next) => {
    try {
        const { token, newPassword } = req.body;

        //Validar que todos los campos sean obligatorios
        if (!token || !newPassword) {
            return res.status(400).json({ error: "Todos los campos son obligatorios" });
        }
        // Iniciar transacción
        await pool.query("BEGIN");

        const result = await pool.query("SELECT reset_token, reset_expires FROM users WHERE reset_token = $1", [token]);
        if (result.rows.length === 0) {
            return res.status(401).json({ message: "Token no valido" });
        }
        //Validar que el token no haya expirado
        const { reset_expires } = result.rows[0];
        if (reset_expires < new Date()) {
            await pool.query("UPDATE users SET reset_token = NULL, reset_expires = NULL WHERE reset_token = $1", [token]);
            return res.status(401).json({ message: "Token expirado" });
        }
        //Encriptar la nueva contraseña
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        await pool.query("UPDATE users SET password = $1, updated_at = NOW(), reset_token = NULL, reset_expires = NULL WHERE reset_token = $2 RETURNING *", [hashedPassword, token]);

        // Confirmar la transacción
        await pool.query("COMMIT");

        res.status(200).json({ message: 'Contraseña cambiada correctamente' });
    } catch (error) {
        await pool.query("ROLLBACK"); // Revertir cambios si algo falla
        next(error);
    }
};

//Metodo eliminar un usurio (solo administradores)
const deleteUser = async (req, res, next) => {
    try {
        const { user_id } = req.params;
        if (!user_id) {
            return res.status(400).json({ message: "Ingrese el id del usuario" });
        }
        await pool.query("DELETE FROM users WHERE user_id = $1", [user_id]);
        res.status(204).json({ message: "Usuario eliminado correctamente" });
    } catch (error) {
        next(error);
    };
};

const assignRole = async (req, res, next) => {
    try {
        const { user_id, role_id } = req.body;
        if (!user_id || !role_id) {
            return res.status(400).json({ message: 'Ingrese los valores' });
        }
        const result = await pool.query("UPDATE users SET role_id = $1, updated_at = NOW()  WHERE user_id =$2", [role_id, user_id]);
        res.status(200).json({ message: 'Rol actuliazado' })
    } catch (error) {
        next(error);
    }
}

//Metodo para listar todos los usuarios
const listUsers = async (req, res, next) => {
    try {
        const result = await pool.query("SELECT \
            u.user_id,\
            u.username,\
            u.email,\
            r.role_name,\
            TO_CHAR(u.created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at,\
            TO_CHAR(u.updated_at, 'YYYY-MM-DD HH24:MI:SS') AS updated_at\
            FROM users u \
            JOIN roles r ON u.role_id = r.role_id");

        res.status(200).json(result.rows);
    } catch (error) {
        next(error);
    }
}

//Exportar todos los metodos
export const methods = {
    registerUsuer,
    loginUser,
    changePassword,
    recoverPasswordEmail,
    resetPassword,
    deleteUser,
    assignRole,
    listUsers
}