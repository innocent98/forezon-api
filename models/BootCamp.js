const mongoose = require("mongoose");

const BootCampSchema = new mongoose.Schema(
  {
    email: {
      type: String,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("BootCamp", BootCampSchema);
