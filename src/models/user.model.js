import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      minlength: [2, "Name must be at least 2 characters long"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, "Please enter a valid email"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters long"],
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    avatar: {
      type: String,
      default: "",
    },
    settings: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
      default: {},
    },
    lastLogin: {
      type: Date,
    },
  },
  {
    timestamps: true, // Adds createdAt and updatedAt fields
    collation: { locale: "en", strength: 2 }, // Case-insensitive unique index
  }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.matchPassword = async function (enteredPassword) {
  try {
    return await bcrypt.compare(enteredPassword, this.password);
  } catch (error) {
    throw new Error("Password comparison failed");
  }
};

// Method to return user data without sensitive information
userSchema.methods.toAuthJSON = function () {
  return {
    _id: this._id,
    name: this.name,
    email: this.email,
    isAdmin: this.isAdmin,
    avatar: this.avatar,
    settings: this.settings,
    createdAt: this.createdAt,
  };
};

const User = mongoose.model("User", userSchema);

export default User;
