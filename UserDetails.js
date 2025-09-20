const mongoose = require("mongoose");

const AudioSchema = new mongoose.Schema({
  fileName: String,
  fileUri: String,
  publicId: String,
  createdAt: { type: Date, default: Date.now },
});

const UserDetailSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String,
  otp: String,
  resetTokenExpiration: Date,
 generatedAudio: {
  type: [AudioSchema],
  default: []
 },
 clonedAudio: {
  type: [AudioSchema],
  default: []
 }
}, {
  collection: "UserInfo"
});

mongoose.model("UserInfo", UserDetailSchema);