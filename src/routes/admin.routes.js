import express from "express";
import { verifyToken } from "../middleware/verifyToken.js";
import { deleteUser, getAllUsers } from "../controllers/admin.controller.js";
import { Order } from "../models/order.model.js"; // Add this import
import Product from "../models/product.model.js"; // <-- Add this import
import {
  createProduct,
  updateProduct,
  deleteProduct,
} from "../controllers/product.controller.js";
import { upload } from "../config/multer.js";
import { protect, admin } from "../middleware/auth.middleware.js";
import { body } from "express-validator";

const router = express.Router();

// Use both protect and admin middleware for all admin routes
router.use(protect);
router.use(admin);

router.use(verifyToken);

// Validation middleware (reuse from product.routes.js)
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

// get all the registered users
router.get("/get-all-users", getAllUsers);

router.delete("/delete-user/:id", deleteUser);

// Get all products (admin only, for dashboard stats)
router.get("/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Failed to fetch products", error: error.message });
  }
});

// Get all orders (admin only)
router.get("/orders", async (req, res) => {
  try {
    const orders = await Order.find()
      .sort({ createdAt: -1 })
      .populate("items.product")
      .populate("user", "name email");
    res.json(orders);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Failed to fetch orders", error: error.message });
  }
});

// Add product (admin only)
router.post(
  "/products",
  protect,
  admin,
  upload.array("images", 5),
  validateProduct,
  createProduct
);

// Update product (admin only)
router.put(
  "/products/:id",
  protect,
  admin,
  upload.array("images", 5),
  updateProduct
);

// Delete product (admin only)
router.delete("/products/:id", protect, admin, deleteProduct);

export default router;
