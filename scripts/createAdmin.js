import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from '../models/user.model.js';

dotenv.config();

const createAdmin = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    const password = 'admin123';
    const hashedPassword = await bcrypt.hash(password, 10);

    const adminUser = {
      name: 'Admin',
      email: 'admin@printo.com',
      password: hashedPassword,
      isAdmin: true
    };

    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminUser.email });
    if (existingAdmin) {
      console.log('Admin user already exists');
      await mongoose.disconnect();
      return;
    }

    // Create new admin
    const newAdmin = await User.create(adminUser);
    console.log('Admin user created successfully:', {
      name: newAdmin.name,
      email: newAdmin.email,
      isAdmin: newAdmin.isAdmin
    });

    await mongoose.disconnect();
  } catch (error) {
    console.error('Error creating admin:', error);
  }
};

createAdmin();
