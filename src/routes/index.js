/**
 * Central router index file
 * This file exports all route modules for cleaner imports in server.js
 */

import express from "express";
import authRoutes from "./auth.routes.js";
import userRoutes from "./user.routes.js";
import productRoutes from "./product.routes.js";
import templateRoutes from "./template.routes.js";
import orderRoutes from "./order.routes.js";

export { authRoutes, userRoutes, productRoutes, templateRoutes, orderRoutes };

// Setup function to register all routes with an Express app
export const setupRoutes = (app) => {
  const router = express.Router();

  router.use("/auth", authRoutes);
  router.use("/users", userRoutes);
  router.use("/products", productRoutes);
  router.use("/templates", templateRoutes);
  router.use("/orders", orderRoutes);

  // Add 404 handler for API routes
  router.use((req, res) => {
    res.status(404).json({ message: "API route not found" });
  });

  app.use(router);
  return app;
};
