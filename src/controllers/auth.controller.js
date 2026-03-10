import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import { use } from "react";

const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { id: user._id, email: user.email, isAdmin: user.isAdmin },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "15m" }
  );

  const refreshToken = jwt.sign(
    { id: user._id, email: user.email, isAdmin: user.isAdmin },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }
  );

  return { accessToken, refreshToken };
};

const setTokenCookie = (res, token, isAccessToken = false) => {
  res.cookie(isAccessToken ? "accessToken" : "refreshToken", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: isAccessToken ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000,
  });
};

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password,
      isAdmin: false,
    });

    const { accessToken, refreshToken } = generateTokens(user);

    // Set both tokens as cookies
    setTokenCookie(res, accessToken, true);
    setTokenCookie(res, refreshToken);

    res.status(201).json({
      message: "User registered successfully",
      user: user.toAuthJSON(),
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Internal server error",
      errors: process.env.NODE_ENV === "development" ? error.errors : undefined,
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    console.log("Found user:", user ? "Yes" : "No");

    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const { accessToken, refreshToken } = generateTokens(user);

    // Set both tokens
    setTokenCookie(res, accessToken, true); // Set access token
    setTokenCookie(res, refreshToken); // Set refresh token

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    res.json({
      message: "User logged in successfully",
      user: user.toAuthJSON(),
      token: accessToken, // Include access token in response
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(400).json({ message: error.message });
  }
};

export const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token required" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
      generateTokens(user);

    setTokenCookie(res, newRefreshToken);

    res.json({
      user: user.toAuthJSON(),
      token: newAccessToken,
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    res.clearCookie("refreshToken");
    res.status(401).json({ message: "Invalid or expired refresh token" });
  }
};

export const adminLogin = async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await User.findOne({ email, isAdmin: true });

    if (!admin || !(await admin.matchPassword(password))) {
      return res.status(401).json({ message: "Invalid admin credentials" });
    }

    const { accessToken, refreshToken } = generateTokens(admin);
    setTokenCookie(res, refreshToken);

    admin.lastLogin = new Date();
    await admin.save();

    res.json({
      user: admin.toAuthJSON(),
      token: accessToken,
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const logout = async (req, res) => {
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.json({ message: "Logged out successfully" });
};

export const me = async (req, res) => {
  try {
    const user = req.user; // User is set by the protect middleware
    if (!user) {
      return res.status(401).json({ message: "User not authenticated" });
    }

    res.json({
      user: user.toAuthJSON(),
    });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
