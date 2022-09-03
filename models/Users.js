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
    },
    referral: {
      type: String,
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    accountBalance: {
      type: Number,
      default: 0,
    },
    investedAmount: {
      type: Number,
      default: 0,
    },
    dailyProfit: {
      type: Number,
      default: 0,
    },
    totalWithdrawal: {
      type: Number,
      default: 0,
    },
    accessToken: {
      type: String,
    },
    time: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Users", UserSchema);
