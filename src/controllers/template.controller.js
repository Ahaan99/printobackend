import { Template } from "../models/template.model.js";
import cloudinary from "../config/cloudinary.js";
import fs from "fs";

export const createTemplate = async (req, res) => {
  try {
    const { name, description, category, baseProduct } = req.body;
    let images = { front: {}, back: {} };

    // Handle front image upload
    if (req.files.frontImage) {
      const result = await cloudinary.uploader.upload(
        req.files.frontImage[0].path,
        {
          folder: "printo/templates",
        }
      );
      images.front = {
        url: result.secure_url,
        public_id: result.public_id,
      };
      fs.unlinkSync(req.files.frontImage[0].path);
    }

    // Handle back image upload (if provided)
    if (req.files.backImage) {
      const result = await cloudinary.uploader.upload(
        req.files.backImage[0].path,
        {
          folder: "printo/templates",
        }
      );
      images.back = {
        url: result.secure_url,
        public_id: result.public_id,
      };
      fs.unlinkSync(req.files.backImage[0].path);
    }

    const template = await Template.create({
      name,
      description,
      category,
      baseProduct,
      images,
      createdBy: req.user._id,
    });

    res.status(201).json(template);
  } catch (error) {
    // Cleanup uploaded files if any error occurs
    if (req.files) {
      Object.values(req.files)
        .flat()
        .forEach((file) => {
          if (fs.existsSync(file.path)) {
            fs.unlinkSync(file.path);
          }
        });
    }
    res.status(400).json({ message: error.message });
  }
};

export const getTemplates = async (req, res) => {
  try {
    const templates = await Template.find({}).populate("baseProduct");
    res.json(templates);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const updateTemplate = async (req, res) => {
  try {
    const template = await Template.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true }
    );
    if (!template) {
      return res.status(404).json({ message: "Template not found" });
    }
    res.json(template);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export const deleteTemplate = async (req, res) => {
  try {
    const template = await Template.findById(req.params.id);
    if (!template) {
      return res.status(404).json({ message: "Template not found" });
    }

    // Delete images from Cloudinary
    if (template.images.front.public_id) {
      await cloudinary.uploader.destroy(template.images.front.public_id);
    }
    if (template.images.back.public_id) {
      await cloudinary.uploader.destroy(template.images.back.public_id);
    }

    await template.deleteOne();
    res.json({ message: "Template deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
