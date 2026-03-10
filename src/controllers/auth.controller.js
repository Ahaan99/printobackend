import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

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

const cookieOptions = (isAccessToken = false) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "none",
  path: "/",
  maxAge: isAccessToken ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000,
});

const setTokenCookies = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, cookieOptions(true));
  res.cookie("refreshToken", refreshToken, cookieOptions(false));
};

const clearTokenCookies = (res) => {
  const clearOpts = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "none",
    path: "/",
  };
  res.clearCookie("accessToken", clearOpts);
  res.clearCookie("refreshToken", clearOpts);
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
    setTokenCookies(res, accessToken, refreshToken);

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

    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const { accessToken, refreshToken } = generateTokens(user);

    // Set both tokens as httpOnly cookies only — no tokens in response body
    setTokenCookies(res, accessToken, refreshToken);

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    res.json({
      message: "User logged in successfully",
      user: user.toAuthJSON(),
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(400).json({ message: error.message });
  }
};

export const refreshToken = async (req, res) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token) {
      return res.status(401).json({ message: "Refresh token required" });
    }

    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
      generateTokens(user);

    // Set BOTH new cookies
    setTokenCookies(res, newAccessToken, newRefreshToken);

    res.json({
      user: user.toAuthJSON(),
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    clearTokenCookies(res);
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

    // Set BOTH tokens as httpOnly cookies
    setTokenCookies(res, accessToken, refreshToken);

    admin.lastLogin = new Date();
    await admin.save();

    res.json({
      user: admin.toAuthJSON(),
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const logout = async (req, res) => {
  clearTokenCookies(res);
  res.json({ message: "Logged out successfully" });
};

export const me = async (req, res) => {
  try {
    const user = req.user; // User is set by the verifyToken middleware
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
