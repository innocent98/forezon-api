const mongoose = require("mongoose");

const WithdrawSchema = new mongoose.Schema(
  {
    uuid: {
      type: String,
    },
    wallet: {
      type: String,
    },
    amount: {
      type: Number,
    },
    isConfirmed: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Withdraw", WithdrawSchema);
