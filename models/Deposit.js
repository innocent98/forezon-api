const mongoose = require("mongoose");

const DepositSchema = new mongoose.Schema(
  {
    uuid: {
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

module.exports = mongoose.model("Deposit", DepositSchema);
