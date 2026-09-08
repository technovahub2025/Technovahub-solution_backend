import { Readable } from "stream";
import cloudinary from "../config/cloudinary.js";
import { getDriveClient } from "../config/googleDrive.js";
import Gallery from "../models/GalleryModels.js";

const uploadToGoogleDrive = async (file) => {
  const drive = await getDriveClient();
  const fileName = `${Date.now()}-${file.originalname || "image"}`;
  const folderId = process.env.GOOGLE_DRIVE_FOLDER_ID;

  const createResponse = await drive.files.create({
    requestBody: {
      name: fileName,
      ...(folderId ? { parents: [folderId] } : {}),
    },
    media: {
      mimeType: file.mimetype,
      body: Readable.from(file.buffer),
    },
    fields: "id,webViewLink",
    supportsAllDrives: true,
  });

  const driveFileId = createResponse.data.id;

  await drive.permissions.create({
    fileId: driveFileId,
    requestBody: { role: "reader", type: "anyone" },
    supportsAllDrives: true,
  });

  return {
    driveFileId,
    imageUrl: `https://drive.google.com/uc?export=view&id=${driveFileId}`,
  };
};

export const uploadImages = async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: "Images are required" });
    }

    const results = await Promise.all(
      req.files.map((file) => uploadToGoogleDrive(file))
    );

    const galleryItems = results.map((result) => ({
      imageUrl: result.imageUrl,
      driveFileId: result.driveFileId,
      storageProvider: "google-drive",
    }));

    const savedImages = await Gallery.insertMany(galleryItems);
    res.status(201).json(savedImages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const getImages = async (req, res) => {
  try {
    const images = await Gallery.find().sort({ createdAt: -1 });
    res.json(images);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const getImage = async (req, res) => {
  try {
    const image = await Gallery.findById(req.params.id);
    if (!image) return res.status(404).json({ message: "Image not found" });
    res.json(image);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const deleteImage = async (req, res) => {
  try {
    const image = await Gallery.findById(req.params.id);
    if (!image) return res.status(404).json({ message: "Image not found" });

    if (image.driveFileId) {
      const drive = await getDriveClient();
      await drive.files.delete({
        fileId: image.driveFileId,
        supportsAllDrives: true,
      });
    } else if (image.publicId) {
      await cloudinary.uploader.destroy(image.publicId);
    }

    await Gallery.findByIdAndDelete(req.params.id);
    res.json({ message: "Image deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
