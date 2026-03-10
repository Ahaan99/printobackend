import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import publicRoutes from "./routes/public.routes.js";
import authRoutes from "./routes/auth.routes.js";
import userRoutes from "./routes/user.routes.js";
import templateRoutes from "./routes/template.routes.js";
import productRoutes from "./routes/product.routes.js";
import orderRoutes from "./routes/order.routes.js";
import { initializeAdmin } from "../init/adminInit.js";

import AdminRoute from "./routes/admin.routes.js";

// Load env vars
dotenv.config();

// Validate required environment variables
const requiredEnvVars = ["MONGODB_URI", "JWT_SECRET", "JWT_REFRESH_SECRET"];
const missingEnvVars = requiredEnvVars.filter(
  (varName) => !process.env[varName]
);
if (missingEnvVars.length > 0) {
  console.error(
    "❌ Missing required environment variables:",
    missingEnvVars.join(", ")
  );
  process.exit(1);
}

// Initialize Express app
const app = express();

// Connect to database
console.log("Connecting to MongoDB...", process.env.MONGODB_URI);
mongoose
  .connect(process.env.MONGODB_URI, {
    // Add these options to handle deprecation warnings and index management
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(async () => {
    console.log("✅ MongoDB Connected Successfully");

    // Optional: Rebuild indexes to ensure they're clean
    try {
      await mongoose.connection.db.collection("users").dropIndexes();
      console.log("✅ User indexes dropped and will be rebuilt");
    } catch (err) {
      console.log("Note: No existing indexes to drop");
    }

    // Initialize admin account after successful DB connection
    initializeAdmin().catch((err) =>
      console.error("Admin initialization error:", err)
    );
  })
  .catch((err) => {
    console.error("❌ MongoDB Connection Error:", err);
    process.exit(1);
  });

// Global Middleware
app.use(cookieParser()); // Add cookie parser
const allowedOrigins = [
  "http://localhost:5173",
  "https://frontendprinto-production.up.railway.app"
];
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security headers middleware
app.use((req, res, next) => {
  res.header("Cross-Origin-Resource-Policy", "cross-origin");
  res.header("X-Content-Type-Options", "nosniff");
  res.header("X-XSS-Protection", "1; mode=block");
  next();
});

app.use("/api/auth", authRoutes);

app.use("/api/admin", AdminRoute);

app.use("/api/public", publicRoutes);

app.use("/api/user/product", productRoutes);

// Protected routes with /api prefix
const apiRouter = express.Router();
app.use("/api", apiRouter);

// Route registration

apiRouter.use("/users", userRoutes);
apiRouter.use("/templates", templateRoutes);
apiRouter.use("/orders", orderRoutes);

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  const statusCode = err.statusCode || 500;
  const message = err.message || "Something went wrong!";
  res.status(statusCode).json({
    message,
    stack: process.env.NODE_ENV === "production" ? "🥞" : err.stack,
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(
    `Server running in ${process.env.NODE_ENV || "development"
    } mode on port ${PORT}`
  );
});
