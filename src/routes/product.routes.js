// file: backend/src/routes/product.routes.js
import express from "express";
import { body } from "express-validator";
import { protect, admin } from "../middleware/auth.middleware.js";
import { upload } from "../config/multer.js";
import {
  createProduct,
  getProductById,
  updateProduct,
  deleteProduct,
  addToCart,
  getUserCart,
  getAllProducts,
  removeFromCart,
  clearCart,
} from "../controllers/product.controller.js";
import { verifyToken } from "../middleware/verifyToken.js";
import Cart from "../models/cart.model.js";

const router = express.Router();

// Validation middleware
const validateProduct = [
  body("name").trim().notEmpty().withMessage("Product name is required"),
  body("description").trim().notEmpty().withMessage("Description is required"),
  body("price")
    .isFloat({ min: 0 })
    .withMessage("Price must be a positive number"),
  body("category")
    .isIn([
      "t-shirts",
      "hoodies",
      "tops",
      "shirts",
      "jackets",
      "sweaters",
      "dresses",
      "blouses",
      "polo",
    ])
    .withMessage("Invalid category"),
  body("gender").isIn(["men", "women", "unisex"]).withMessage("Invalid gender"),
  body("colors").isArray().withMessage("Colors must be an array"),
  body("sizes").isArray().withMessage("Sizes must be an array"),
];

// Create product - with validation
router.post(
  "/",
  protect,
  admin,
  upload.array("images", 5),
  validateProduct,
  createProduct
);

// Get all products
router.get("/", getAllProducts);

// Get single product by ID
router.get("/:id", getProductById);

// Update product
router.put("/:id", protect, admin, upload.array("images", 5), updateProduct);

// Delete product
router.delete("/:id", verifyToken, deleteProduct);

router.post("/:id/cart", verifyToken, addToCart);

// Use controller for current user's cart
router.get("/:userId/cart", verifyToken, getUserCart);

// Add to cart for a specific user
router.post("/:userId/add-to-cart", verifyToken, addToCart);

// Add product for a specific user (matches AddProduct.jsx usage)
router.post(
  "/:userId/add",
  verifyToken,
  upload.array("images", 5),
  createProduct
);

// Remove from cart for a specific user
router.post("/:userId/remove-from-cart", verifyToken, removeFromCart);

// Clear cart for a specific user
router.post("/:userId/clear-cart", verifyToken, clearCart);

export default router;
