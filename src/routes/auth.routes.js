import { Router } from 'express';
import { methods as authController } from '../controllers/auth.controller.js';

const router = Router();

//Rutas publicas
router.post("/login", authController.loginUser);

//Rutas protegidas para Administradores
router.post("/register", authController.registerUsuer);


export default router;