import User from "../models/user.model.js";
import bcrypt from "bcryptjs";

// Admin: Get all users
export const getUsers = async (req, res) => {
  const page = Number(req.query.page) || 1;
  const limit = 10;
  const skip = (page - 1) * limit;

  const users = await User.find().skip(skip).limit(limit).select("-password");
  res.json(users);
};

// Admin: Activate user
export const activateUser = async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { status: "active" });
  res.json({ message: "User activated" });
};

// Admin: Deactivate user
export const deactivateUser = async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { status: "inactive" });
  res.json({ message: "User deactivated" });
};

// User: Update profile
export const updateProfile = async (req, res) => {
  const { fullName, email } = req.body;

  const user = await User.findByIdAndUpdate(
    req.user.id,
    { fullName, email },
    { new: true }
  ).select("-password");

  res.json(user);
};

// User: Change password
export const changePassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user.id);

  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Wrong old password" });
  }

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();

  res.json({ message: "Password updated" });
};
