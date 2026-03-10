import express from "express";
import { body } from "express-validator";
import { protect, admin } from "../middleware/auth.middleware.js";
import {
  getProfile,
  updateProfile,
  updateAvatar,
  updatePassword,
  updateSettings,
  deleteAccount,
  exportUserData,
  getAllUsers,
  getUserById,
  deleteUser,
} from "../controllers/user.controller.js";
import { validateRequest } from "../middleware/validation.middleware.js";
import { rateLimiter } from "../middleware/rateLimit.middleware.js";
import { verifyToken } from "../middleware/verifyToken.js";
import { upload } from "../config/multer.js";

const router = express.Router();

/**
 * Protected User Routes
 * All routes below this point require authentication
 */

router.use(protect); // Apply protect middleware to all routes

router.get("/profile", verifyToken, getProfile);

router.put(
  "/profile",
  [
    body("name")
      .optional()
      .trim()
      .notEmpty()
      .withMessage("Name cannot be empty"),
    body("email")
      .optional()
      .isEmail()
      .withMessage("Please include a valid email"),
    validateRequest,
  ],
  verifyToken,
  updateProfile
);

/**
 * @route   PUT /api/users/profile/avatar
 * @desc    Update user avatar
 * @access  Private
 */
router.put("/profile/avatar", verifyToken, upload.single("avatar"), updateAvatar);

/**
 * @route   PUT /api/users/profile/password
 * @desc    Update user password
 * @access  Private
 */
router.put(
  "/profile/password",
  [
    rateLimiter({ windowMs: 60 * 60 * 1000, max: 3 }), // 3 password changes per hour
    body("currentPassword")
      .exists()
      .withMessage("Current password is required"),
    body("newPassword")
      .isLength({ min: 8 })
      .withMessage("New password must be at least 8 characters")
      .matches(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
      )
      .withMessage(
        "Password must contain at least one uppercase letter, one lowercase letter, one number and one special character"
      ),
    validateRequest,
  ],
  updatePassword
);

/**
 * @route   PUT /api/users/settings
 * @desc    Update user settings
 * @access  Private
 */
router.put(
  "/settings",
  [
    body("settings").isObject().withMessage("Settings must be an object"),
    validateRequest,
  ],
  updateSettings
);

/**
 * @route   DELETE /api/users/account
 * @desc    Delete user account
 * @access  Private
 */
router.delete(
  "/account",
  [
    rateLimiter({ windowMs: 24 * 60 * 60 * 1000, max: 1 }), // 1 account deletion per day
    body("password")
      .exists()
      .withMessage("Password is required for account deletion"),
    validateRequest,
  ],
  deleteAccount
);

/**
 * @route   GET /api/users/export
 * @desc    Export user data
 * @access  Private
 */
router.get("/export", exportUserData);

/**
 * Admin Routes
 * All routes below this point require admin privileges
 */

router.use(admin); // Apply admin middleware to all admin routes

router.get("/", getAllUsers);
router.get("/:id", getUserById);
router.delete("/:id", deleteUser);

export default router;