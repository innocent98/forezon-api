const mongoose = require("mongoose");

const AdminSchema = new mongoose.Schema(
  {
    wallet: {
      type: String,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Admins", AdminSchema);
