const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
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
      default: false,
    },
    accountBalance: {
      type: Number,
    },
    investedAmount: {
      type: Number,
    },
    dailyProfit: {
      type: Number,
    },
    totalWithdrawal: {
      type: Number,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Users", UserSchema);
