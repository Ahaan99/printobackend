import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protect = async (req, res, next) => {
  try {
    // Get tokens from cookies
    const accessToken = req.cookies.accessToken;
    const refreshToken = req.cookies.refreshToken;

    // Check if access token exists
    if (!accessToken) {
      if (!refreshToken) {
        return res.status(401).json({
          message: "Authentication required",
          code: "NO_TOKEN",
        });
      }
      // Try to refresh the access token
      try {
        const decoded = jwt.verify(
          refreshToken,
          process.env.JWT_REFRESH_SECRET
        );
        const user = await User.findById(decoded.id).select("-password");

        if (!user) {
          return res.status(401).json({
            message: "User not found",
            code: "USER_NOT_FOUND",
          });
        }

        // Generate new tokens
        const { accessToken: newAccessToken } = generateTokens(user);
        res.cookie("accessToken", newAccessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 24 * 60 * 60 * 1000, // 24 hours
        });

        req.user = user;
        next();
      } catch (error) {
        return res.status(401).json({
          message: "Session expired",
          code: "SESSION_EXPIRED",
        });
      }
      return;
    }

    // Verify access token
    try {
      const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select("-password");

      if (!user) {
        return res.status(401).json({
          message: "User not found",
          code: "USER_NOT_FOUND",
        });
      }

      req.user = user;
      next();
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        res.clearCookie("accessToken");
        return res.status(401).json({
          message: "Access token expired",
          code: "TOKEN_EXPIRED",
        });
      }
      throw error;
    }
  } catch (error) {
    console.error("[Auth Middleware] Error:", error);
    res.status(401).json({
      message: "Authentication failed",
      code: "AUTH_FAILED",
    });
  }
};

export const admin = (req, res, next) => {
  if (!req.user) {
    console.log("[Admin Middleware] No user in request");
    return res.status(401).json({ message: "Not authenticated" });
  }

  if (!req.user.isAdmin) {
    console.log("[Admin Middleware] User not admin:", req.user._id);
    return res.status(403).json({ message: "Not authorized as admin" });
  }

  console.log("[Admin Middleware] Admin access granted:", req.user._id);
  next();
};
