import mongoose from "mongoose";

const orderSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  items: [
    {
      product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product",
        required: true,
      },
      name: String,
      price: Number,
      quantity: Number,
      size: String,
      color: String,
      customization: {
        type: Object,
        default: null,
      },
    },
  ],
  shippingAddress: {
    name: { type: String, required: true },
    email: String,
    phone: { type: String, required: true },
    address: { type: String, required: true },
    city: String,
    state: String,
    pincode: { type: String, required: true },
  },
  status: {
    type: String,
    enum: ["pending", "processing", "shipped", "delivered", "cancelled"],
    default: "pending",
  },
  subtotal: Number,
  total: Number,
  shippingCost: {
    type: Number,
    default: 0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

orderSchema.pre("save", function (next) {
  if (!this.subtotal) {
    this.subtotal = this.items.reduce(
      (total, item) => total + item.price * item.quantity,
      0
    );
  }
  if (typeof this.shippingCost !== "number") {
    this.shippingCost = 0; // or set your shipping logic here
  }
  if (!this.total) {
    this.total = this.subtotal + this.shippingCost; // Add shipping cost to total
  }
  next();
});

export const Order = mongoose.model("Order", orderSchema);
