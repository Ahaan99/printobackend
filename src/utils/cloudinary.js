// file: backend/src/utils/cloudinary.js
import { v2 as cloudinary } from "cloudinary";
import fs from "fs";
import dotenv from "dotenv";

dotenv.config();

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

/**
 * Upload a file to Cloudinary
 * @param {string} filePath - The path to the file to upload
 * @param {string} folder - The folder to upload to in Cloudinary
 * @returns {Promise} - The upload result
 */
export const uploadToCloudinary = async (filePath, folder = "uploads") => {
  try {
    const result = await cloudinary.uploader.upload(filePath, {
      folder: folder,
      resource_type: "auto",
    });

    // Clean up the temporary file after successful upload
    fs.unlinkSync(filePath);

    return result;
  } catch (error) {
    // Clean up the temporary file in case of error
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    throw error;
  }
};

/**
 * Delete a file from Cloudinary
 * @param {string} publicId - The public ID of the file to delete
 * @returns {Promise} - The deletion result
 */
export const deleteFromCloudinary = async (publicId) => {
  try {
    // Extract public_id from URL if a full URL is provided
    if (publicId.startsWith("http")) {
      // Example URL: https://res.cloudinary.com/your-cloud-name/image/upload/v1234567890/folder/image.jpg
      const splitUrl = publicId.split("/");
      const filenameWithExtension = splitUrl[splitUrl.length - 1];
      const filename = filenameWithExtension.split(".")[0];
      const folder = splitUrl[splitUrl.length - 2];
      publicId = `${folder}/${filename}`;
    }

    const result = await cloudinary.uploader.destroy(publicId);
    return result;
  } catch (error) {
    console.error("Error deleting from Cloudinary:", error);
    throw error;
  }
};

/**
 * Get the public ID from a Cloudinary URL
 * @param {string} url - The Cloudinary URL
 * @returns {string} - The public ID
 */
export const getPublicIdFromUrl = (url) => {
  try {
    const splitUrl = url.split("/");
    const filenameWithExtension = splitUrl[splitUrl.length - 1];
    const filename = filenameWithExtension.split(".")[0];
    const folder = splitUrl[splitUrl.length - 2];
    return `${folder}/${filename}`;
  } catch (error) {
    console.error("Error extracting public ID:", error);
    return null;
  }
};
