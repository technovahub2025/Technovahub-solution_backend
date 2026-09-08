import mongoose from "mongoose";

const googleDriveTokenSchema = new mongoose.Schema(
  {
    provider: { type: String, unique: true, default: "google-drive" },
    encryptedRefreshToken: { type: String, required: true },
  },
  { timestamps: true }
);

const GoogleDriveToken = mongoose.model("GoogleDriveToken", googleDriveTokenSchema);
export default GoogleDriveToken;
