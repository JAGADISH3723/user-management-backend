import express from "express";
import authMiddleware from "../middlewares/auth.middleware.js";
import roleMiddleware from "../middlewares/role.middleware.js";
import {
  getUsers,
  activateUser,
  deactivateUser,
  updateProfile,
  changePassword
} from "../controllers/user.controller.js";

const router = express.Router();

router.get("/", authMiddleware, roleMiddleware("admin"), getUsers);
router.patch("/:id/activate", authMiddleware, roleMiddleware("admin"), activateUser);
router.patch("/:id/deactivate", authMiddleware, roleMiddleware("admin"), deactivateUser);

router.put("/profile", authMiddleware, updateProfile);
router.put("/change-password", authMiddleware, changePassword);

export default router;
