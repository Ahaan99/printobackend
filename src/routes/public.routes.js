// routes/publicRoutes.js
import express from "express";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

const router = express.Router();

router.post("/refresh", async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "No refresh token provided" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.json({ user: user.toAuthJSON() });
  } catch (err) {
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.status(403).json({ message: "Invalid or expired refresh token" });
  }
});

export default router;
