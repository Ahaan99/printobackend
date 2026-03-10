import bcrypt from "bcryptjs";
import User from "../src/models/user.model.js";

const SALT_ROUNDS = 10;

export const initializeAdmin = async (force = false) => {
  try {
    // Delete existing admin if force flag is set
    if (force) {
      console.log("Force flag set, removing existing admin...");
      await User.deleteMany({ isAdmin: true });
    }

    const adminExists = await User.findOne({ email: "admin@printo.com" });
    if (adminExists) {
      console.log("Admin already exists, skipping...");
      return;
    }

    const password = "admin123";
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const hashedPassword = await bcrypt.hash(password, salt);

    console.log(
      "Creating new admin with hash:",
      hashedPassword.substring(0, 10) + "..."
    );

    const adminUser = new User({
      name: "Admin",
      email: "admin@printo.com",
      password: password, // Will be hashed by pre-save middleware
      isAdmin: true,
    });

    await adminUser.save();
    console.log("Admin created successfully");
  } catch (error) {
    console.error("Admin initialization error:", error);
  }
};
