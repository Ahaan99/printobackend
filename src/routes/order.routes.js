import express from "express";
import { protect } from "../middleware/auth.middleware.js";
import {
  createOrder,
  getOrders,
  getOrderById,
  updateOrderStatus,
  cancelOrder,
} from "../controllers/order.controller.js";

const router = express.Router();

// Create new order
router.post("/", protect, createOrder);

// Get user's orders
router.get("/", protect, getOrders);

// Get specific order
router.get("/:id", protect, getOrderById);

// Update order status (admin only)
router.patch("/:id/status", protect, updateOrderStatus);

// Cancel order (user)
router.patch("/:id/cancel", protect, cancelOrder);

export default router;
