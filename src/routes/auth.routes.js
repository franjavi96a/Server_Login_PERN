import { Router } from 'express';
import { verifyToken, isAdmin } from '../middleware/middleware.js';
import { methods as authController } from '../controllers/auth.controller.js';

const router = Router();

//Rutas publicas
router.post("/login", authController.loginUser);
router.post("/recover-password", authController.recoverPasswordEmail);
router.put("/reset-password", authController.resetPassword);


//Rutas que requieren autenticación (usuario logueado)
router.put("/change-password", verifyToken, authController.changePassword);

//Rutas protegidas para Administradores
router.post("/register", verifyToken, isAdmin, authController.registerUsuer);
router.delete("/delete-user/:user_id", verifyToken, isAdmin, authController.deleteUser);
router.put("/assign-role", verifyToken, isAdmin, authController.assignRole);
router.get("/list-users", verifyToken, isAdmin, authController.listUsers);


export default router;