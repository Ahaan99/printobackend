import express from "express";
import { body } from "express-validator";
import { validateRequest } from "../middleware/validation.middleware.js";
import {
  register,
  login,
  adminLogin,
  refreshToken,
  logout,
  me,
} from "../controllers/auth.controller.js";
import { protect } from "../middleware/auth.middleware.js";
import { verifyToken } from "../middleware/verifyToken.js";

const router = express.Router();

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post(
  "/register",
  [
    body("name").notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Please include a valid email"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters"),
    validateRequest,
  ],
  register
);

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post(
  "/login",
  [
    body("email").isEmail().withMessage("Please include a valid email"),
    body("password").exists().withMessage("Password is required"),
    validateRequest,
  ],
  login
);

/**
 * @route   POST /api/auth/admin/login
 * @desc    Admin login
 * @access  Public
 */
router.post(
  "/admin/login",
  [
    body("email").isEmail().withMessage("Please include a valid email"),
    body("password").exists().withMessage("Password is required"),
    validateRequest,
  ],
  adminLogin
);

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token
 * @access  Public
 */
router.post("/refresh", refreshToken);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user and clear refresh token
 * @access  Private
 */
router.post("/logout", verifyToken, logout);

/**
 * @route   GET /api/auth/me
 * @desc    Get current user
 * @access  Private
 */
router.post("/me", verifyToken, me);

export default router;
