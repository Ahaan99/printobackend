import express from "express";
import { protect, admin } from "../middleware/auth.middleware.js";
import { upload } from "../config/multer.js";
import {
  createTemplate,
  getTemplates,
  deleteTemplate,
  updateTemplate,
} from "../controllers/template.controller.js";

const router = express.Router();

router.post(
  "/",
  protect,
  admin,
  upload.fields([
    { name: "frontImage", maxCount: 1 },
    { name: "backImage", maxCount: 1 },
  ]),
  createTemplate
);

router.get("/", getTemplates);
router.put("/:id", protect, admin, updateTemplate);
router.delete("/:id", protect, admin, deleteTemplate);

export default router;
