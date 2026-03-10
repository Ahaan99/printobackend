import { Order } from "../models/order.model.js";

// Create new order
export const createOrder = async (req, res) => {
  try {
    const { items, shippingAddress } = req.body;
    const userId = req.user._id;

    // Set your shipping cost logic here (e.g., flat $5)
    const shippingCost = 0; // or 5, or calculate based on items/shippingAddress

    const order = new Order({
      user: userId,
      items,
      shippingAddress,
      shippingCost, // <-- add this line
    });

    await order.save();

    res.status(201).json(order);
  } catch (error) {
    console.error("Create order error:", error);
    res
      .status(500)
      .json({ message: "Failed to create order", error: error.message });
  }
};

// Get user's orders
export const getOrders = async (req, res) => {
  try {
    const userId = req.user._id;
    const orders = await Order.find({ user: userId })
      .sort({ createdAt: -1 })
      .populate("items.product");

    res.json(orders);
  } catch (error) {
    console.error("Get orders error:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch orders", error: error.message });
  }
};

// Get specific order
export const getOrderById = async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate("items.product");

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Check if the order belongs to the user
    if (order.user.toString() !== req.user._id.toString()) {
      return res
        .status(403)
        .json({ message: "Not authorized to view this order" });
    }

    res.json(order);
  } catch (error) {
    console.error("Get order error:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch order", error: error.message });
  }
};

// Update order status (admin only)
export const updateOrderStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Prevent status update if order is cancelled
    if (order.status === "cancelled") {
      return res
        .status(400)
        .json({ message: "Cannot update a cancelled order" });
    }

    // TODO: Add admin check here
    order.status = status;
    await order.save();

    res.json(order);
  } catch (error) {
    console.error("Update order status error:", error);
    res
      .status(500)
      .json({ message: "Failed to update order status", error: error.message });
  }
};

// Cancel order (user)
export const cancelOrder = async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }
    // Only the owner can cancel
    if (order.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "Not authorized" });
    }
    // Cannot cancel if delivered
    if (order.status === "delivered") {
      return res
        .status(400)
        .json({ message: "Cannot cancel a delivered order" });
    }
    if (order.status === "cancelled") {
      return res.status(400).json({ message: "Order already cancelled" });
    }

    order.status = "cancelled";
    await order.save();

    res.json(order);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Failed to cancel order", error: error.message });
  }
};
