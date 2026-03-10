import cloudinary from "../config/cloudinary.js";
import User from "../models/user.model.js";
import {
  uploadToCloudinary,
  deleteFromCloudinary,
} from "../utils/cloudinary.js";

export const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user.toAuthJSON());
  } catch (error) {
    res.status(500).json({ message: "Error fetching profile" });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const { name, email } = req.body;
    const user = req.user;

    if (email && email !== user.email) {
      const emailExists = await User.findOne({ email });
      if (emailExists) {
        return res.status(400).json({ message: "Email already in use" });
      }
      user.email = email;
    }

    if (name) {
      user.name = name;
    }

    const updatedUser = await user.save();

    res.json({
      user: updatedUser.toAuthJSON(),
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export const updateAvatar = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const user = req.user;

    // Upload from buffer using Cloudinary stream
    const streamUpload = (buffer) => {
      return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          {
            folder: "avatars",
            public_id: `avatar-${user._id}`,
            overwrite: true,
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        stream.end(buffer); // pass buffer
      });
    };

    const result = await streamUpload(req.file.buffer); // <== key line
    user.avatar = result.secure_url;
    const updatedUser = await user.save();

    res.status(200).json({ user: updatedUser.toAuthJSON() });
  } catch (error) {
    console.error("Avatar upload error:", error);
    res.status(500).json({ message: "Upload failed" });
  }
};

export const updatePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id);

    if (!user || !(await user.matchPassword(currentPassword))) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    user.password = newPassword;
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export const updateSettings = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.settings = { ...user.settings, ...req.body.settings };
    const updatedUser = await user.save();

    res.json({
      user: updatedUser.toAuthJSON(),
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export const deleteAccount = async (req, res) => {
  try {
    const { password } = req.body;
    const user = await User.findById(req.user._id);

    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ message: "Invalid password" });
    }

    // Delete avatar from cloudinary if exists
    if (user.avatar) {
      await deleteFromCloudinary(user.avatar);
    }

    await user.deleteOne();
    res.json({ message: "Account deleted successfully" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export const exportUserData = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select(
      "-password -passwordResetToken -passwordResetExpires -twoFactorSecret"
    );

    // Add any other related data you want to include in the export
    const userData = {
      profile: user.toAuthJSON(),
      settings: user.settings,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    res.json(userData);
  } catch (error) {
    res.status(500).json({ message: "Error exporting user data" });
  }
};

export const getAllUsers = async (req, res) => {
  try {
    const users = await User.find({}).select("-password");
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Error fetching users" });
  }
};

export const getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ message: "Error fetching user" });
  }
};

export const deleteUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.isAdmin) {
      return res.status(400).json({ message: "Cannot delete admin user" });
    }

    // Delete avatar from cloudinary if exists
    if (user.avatar) {
      await deleteFromCloudinary(user.avatar);
    }

    await user.deleteOne();
    res.json({ message: "User removed" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting user" });
  }
};