// file: backend/src/models/cart.model.js
import mongoose from "mongoose";

const cartSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User", // reference to User model
      required: true,
    },
    items: [
      {
        product: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Product", // reference to Product model
          required: true,
        },
        quantity: {
          type: Number,
          default: 1,
          min: 1,
        },
        size: {
          type: String,
          required: true,
          enum: ["XS", "S", "M", "L", "XL", "XXL"], // keep in sync with product model if you want to enforce
        },
        color: {
          type: String,
          required: true,
        },
        customization: {
          type: Object,
          default: null,
        },
      },
    ],
    total: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true, // adds createdAt and updatedAt
  }
);

// Prevent model overwrite error in dev with hot reload
const Cart = mongoose.models.Cart || mongoose.model("Cart", cartSchema);

export default Cart;
