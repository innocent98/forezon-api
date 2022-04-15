const mongoose = require("mongoose");

const AdminSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      unique: true,
      required: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
      unique: true,
    },
    isAdmin: {
      type: Boolean,
      default: true,
    },
    accessToken: {
      type: String,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Admins", AdminSchema);
