import mongoose from "mongoose";

const gallerySchema = new mongoose.Schema(
  {
    imageUrl: { type: String, required: true },
    publicId: { type: String, default: null },
    driveFileId: { type: String, default: null },
    storageProvider: { type: String, default: "google-drive" },
  },
  { timestamps: true }
);

const Gallery = mongoose.model("Gallery", gallerySchema);
export default Gallery;
