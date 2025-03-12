import { Router } from 'express';
import { verifyToken, isAdmin } from '../middleware/middleware.js';
import { methods as authController } from '../controllers/auth.controller.js';

const router = Router();

//Rutas publicas
router.post("/login", authController.loginUser);

//Rutas que requieren autenticación (usuario logueado)
router.post("/changepassword", verifyToken, authController.changePassword);

//Rutas protegidas para Administradores
router.post("/register", verifyToken, isAdmin, authController.registerUsuer);


export default router;