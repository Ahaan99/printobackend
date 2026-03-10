// file: backend/src/controllers/product.controller.js
import Product from "../models/product.model.js";
import Cart from "../models/cart.model.js"; // Import Cart model
import cloudinary from "../config/cloudinary.js";
import fs from "fs";

export const getAllProducts = async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 }); // newest first
    res.status(200).json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({
      message: "Failed to fetch products",
      error: error.message,
    });
  }
};

export const getProductById = async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (product) {
      res.json(product);
    } else {
      res.status(404).json({ message: "Product not found" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const createProduct = async (req, res) => {
  try {
    const {
      name,
      description,
      price,
      category,
      gender,
      colors,
      sizes,
      stock,
      customizable,
    } = req.body;

    // Parse colors and sizes as arrays if needed
    let colorsArr = colors;
    let sizesArr = sizes;
    if (typeof colors === "string") {
      try {
        colorsArr = JSON.parse(colors);
      } catch {
        colorsArr = [colors];
      }
    }
    if (!Array.isArray(colorsArr)) colorsArr = [colorsArr];
    if (typeof sizes === "string") {
      try {
        sizesArr = JSON.parse(sizes);
      } catch {
        sizesArr = [sizes];
      }
    }
    if (!Array.isArray(sizesArr)) sizesArr = [sizesArr];

    // Upload images from memory
    let images = [];
    if (req.files && req.files.length > 0) {
      const uploadPromises = req.files.map((file) => {
        return new Promise((resolve, reject) => {
          cloudinary.uploader
            .upload_stream(
              {
                folder: "printo/products",
                resource_type: "image",
              },
              (error, result) => {
                if (error) return reject(error);
                resolve({
                  url: result.secure_url,
                  public_id: result.public_id,
                });
              }
            )
            .end(file.buffer); // 👈 Send buffer directly here
        });
      });

      images = await Promise.all(uploadPromises);
    }

    const product = await Product.create({
      name,
      description,
      price: Number(price),
      category,
      gender: gender || "unisex",
      colors: colorsArr,
      sizes: sizesArr,
      stock: Number(stock),
      images,
      customizable: customizable === "true" || customizable === true,
      createdBy: req.user._id,
    });

    res.status(201).json(product);
  } catch (error) {
    console.error("Error creating product:", error);
    res.status(400).json({
      message: "Failed to create product",
      error: error.message,
    });
  }
};

export const updateProduct = async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    // Parse fields from form-data (strings)
    const {
      name,
      description,
      price,
      category,
      gender,
      colors,
      sizes,
      stock,
      removeImages,
      customizable, // <-- add this
    } = req.body;

    // Update basic fields if present
    if (name !== undefined) product.name = name;
    if (description !== undefined) product.description = description;
    if (price !== undefined) product.price = Number(price);
    if (category !== undefined) product.category = category;
    if (gender !== undefined) product.gender = gender;
    if (stock !== undefined) product.stock = Number(stock);
    if (colors !== undefined) {
      let colorsArr = colors;
      if (typeof colors === "string") {
        try {
          colorsArr = JSON.parse(colors);
        } catch {
          colorsArr = [colors];
        }
      }
      if (!Array.isArray(colorsArr)) colorsArr = [colorsArr];
      product.colors = colorsArr;
    }
    if (sizes !== undefined) {
      let sizesArr = sizes;
      if (typeof sizes === "string") {
        try {
          sizesArr = JSON.parse(sizes);
        } catch {
          sizesArr = [sizes];
        }
      }
      if (!Array.isArray(sizesArr)) sizesArr = [sizesArr];
      product.sizes = sizesArr;
    }
    if (customizable !== undefined) {
      product.customizable = customizable === "true" || customizable === true;
    }

    // Remove images if requested (by index)
    if (removeImages) {
      let indexes = [];
      try {
        indexes = JSON.parse(removeImages);
      } catch {}
      // Remove from product.images and delete from cloudinary
      indexes
        .sort((a, b) => b - a) // Remove from end to start to avoid index shift
        .forEach((idx) => {
          const img = product.images[idx];
          if (img && img.public_id) {
            cloudinary.uploader.destroy(img.public_id);
          }
          product.images.splice(idx, 1);
        });
    }

    // Add new images if uploaded
    if (req.files && req.files.length > 0) {
      const uploadPromises = req.files.map((file) => {
        return new Promise((resolve, reject) => {
          cloudinary.uploader
            .upload_stream(
              {
                folder: "printo/products",
                resource_type: "image",
              },
              (error, result) => {
                if (error) return reject(error);
                resolve({
                  url: result.secure_url,
                  public_id: result.public_id,
                });
              }
            )
            .end(file.buffer);
        });
      });
      const newImages = await Promise.all(uploadPromises);
      product.images = product.images.concat(newImages);
    }

    const updatedProduct = await product.save();
    res.json(updatedProduct);
  } catch (error) {
    console.error("Error updating product:", error);
    res
      .status(400)
      .json({ message: "Failed to update product", error: error.message });
  }
};

export const deleteProduct = async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    // Delete images from Cloudinary
    const deletePromises = product.images.map((image) =>
      cloudinary.uploader.destroy(image.public_id)
    );

    await Promise.all(deletePromises);
    await product.deleteOne();
    res.json({ message: "Product removed" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const addToCart = async (req, res) => {
  try {
    const { productId, quantity = 1, size, color, customization } = req.body;
    // Use userId from params if present, else fallback to req.user._id
    const userId = req.params.userId || req.user._id;

    console.log("item data:", req.body);
    if (!productId || !size || !color) {
      return res
        .status(400)
        .json({ message: "Product ID, size, and color are required" });
    }

    const product = await Product.findById(productId);
    console.log("Product found:", product);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    let cart = await Cart.findOne({ user: userId });

    if (!cart) {
      cart = await Cart.create({
        user: userId,
        items: [],
        total: 0,
      });
    }

    const itemIndex = cart.items.findIndex(
      (item) =>
        item.product.toString() === productId &&
        item.size === size &&
        item.color === color &&
        ((!item.customization && !customization) ||
          (item.customization &&
            customization &&
            JSON.stringify(item.customization) ===
              JSON.stringify(customization)))
    );

    if (itemIndex > -1) {
      cart.items[itemIndex].quantity += quantity;
      // Optionally update customization if needed
      if (customization) {
        cart.items[itemIndex].customization = customization;
      }
    } else {
      cart.items.push({
        product: productId,
        quantity,
        size,
        color,
        customization,
      });
    }

    // Step 1: Populate product details
    try {
      await cart.populate("items.product");
    } catch (err) {
      console.error("Cart populate error:", err);
      return res
        .status(500)
        .json({ message: "Cart populate error", error: err.message });
    }

    // Step 2: Recalculate total with actual product prices
    cart.total = cart.items.reduce((total, item) => {
      // Only add if item.product is not null (populated successfully)
      if (item.product && typeof item.product.price === "number") {
        return total + item.quantity * item.product.price;
      }
      // Optionally, you could log or clean up items with missing products here
      return total;
    }, 0);

    await cart.save();

    res.json(cart);
  } catch (error) {
    console.error("Add to cart error:", error);
    res.status(500).json({ message: "Something went wrong" });
  }
};

export const removeFromCart = async (req, res) => {
  try {
    const { productId, size, color } = req.body;
    const userId = req.params.userId || req.user._id;

    if (!productId || !size || !color) {
      return res
        .status(400)
        .json({ message: "Product ID, size, and color are required" });
    }

    let cart = await Cart.findOne({ user: userId }).populate("items.product");
    if (!cart) {
      return res.status(404).json({ message: "Cart not found" });
    }

    // Remove the item matching productId, size, and color
    cart.items = cart.items.filter(
      (item) =>
        !(
          item.product &&
          item.product._id.toString() === productId &&
          item.size === size &&
          item.color === color
        )
    );

    // Recalculate total
    cart.total = cart.items.reduce((total, item) => {
      if (item.product && typeof item.product.price === "number") {
        return total + item.quantity * item.product.price;
      }
      return total;
    }, 0);

    await cart.save();

    res.json(cart);
  } catch (error) {
    console.error("Remove from cart error:", error);
    res.status(500).json({ message: "Something went wrong" });
  }
};

export const getItems = async (req, res) => {
  return res.status(200).json({
    message: "This is a protected route for product items",
  });
};

export const getUserCart = async (req, res) => {
  try {
    const { userId } = req.params;
    // Optional: verify that req.user._id === userId (security check)
    if (!req.user || req.user._id.toString() !== userId) {
      return res.status(403).json({ message: "Forbidden" });
    }

    // Find cart by userId and populate product details
    const cart = await Cart.findOne({ user: userId }).populate("items.product");
    console.log("Cart fetched from DB:", cart);

    if (!cart) {
      return res.json({ items: [], total: 0 });
    }

    res.json(cart);
  } catch (error) {
    console.error("[Backend] Failed to fetch cart:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch cart", error: error.message });
  }
};

export const clearCart = async (req, res) => {
  try {
    const userId = req.params.userId || req.user._id;
    await Cart.findOneAndUpdate(
      { user: userId },
      { $set: { items: [], total: 0 } }
    );
    res.json({ message: "Cart cleared successfully" });
  } catch (error) {
    console.error("Clear cart error:", error);
    res.status(500).json({ message: "Failed to clear cart" });
  }
};
