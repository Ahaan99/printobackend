import User from '../models/user.model.js';
export const getAllUsers = async (req, res) => {
  try {
    // if requestor is not an admin, return unauthorized
    if (!req.user || !req.user.isAdmin) {
      return res.status(403).json({ message: "Unauthorized" });
    }
    // Fetch all registered users from the database
    const users = await User.find();
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const deleteUser = async (req, res) => {
  try {
    const userId = req.params.id;
    // if requestor is not an admin, return unauthorized
    if (!req.user || !req.user.isAdmin) {
      return res.status(403).json({ message: "Unauthorized" });
    }
    // Find and delete the user by ID
    const deletedUser = await User.findByIdAndDelete(userId);
    if (!deletedUser) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "Server error" });
  }
};