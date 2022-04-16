const router = require("express").Router();
const bcrypt = require("bcrypt");
const Users = require("../models/Users");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

//jsonwebtoken
const verify = (req, res, next) => {
  const authHeader = req.body.accessToken;
  if (authHeader) {
    const token = authHeader;

    jwt.verify(token, process.env.JWT_KEY, (err, user) => {
      if (err) {
        console.log(err);
        return res.status(403).json("token is not valid");
      }

      req.user = user;
      next();
    });
  } else {
    res.status(401).json("you are not authenticated");
  }
};

//register a user
router.post("/register", async (req, res) => {
  try {
    // generate aa new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    //create a new user
    const username = req.body.username;
    const email = req.body.email;
    const password = hashedPassword;

    //check is a user exist
    const findUser =
      (await Users.findOne({ email: req.body.email })) ||
      (await Users.findOne({ username: req.body.username }));
    if (!findUser) {
      const newUser = await new Users({
        email,
        username,
        password,
      });
      const user = await newUser.save();
      res
        .status(200)
        .json({ status: "success", message: "User successfully registered" });
    } else {
      res.status(403).json({
        status: "exist",
        message:
          "User with the email or username exist!  Please try another one.",
      });
    }
  } catch (err) {
    res.status(500).json({ status: "error", message: "Connection Error!" });
  }
});

let refreshTokens = [];
//generate refresh token
router.post("/refresh", (req, res) => {
  //take refresh token from user
  const refreshToken = req.body.token;
  if (!refreshToken)
    return res.status(401).json({
      status: "not-authenticated",
      message: "You are not authenticated!",
    });
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ message: "Refresh token is not valid" });
  }
  jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    //create new access token and refresh token if everything is okay
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);

    res
      .status(200)
      .json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  });
});

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.JWT_KEY, {
    expiresIn: "3600s",
  });
};
const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    process.env.JWT_REFRESH_KEY,
    {}
  );
};

//login a user
router.post("/login", async (req, res) => {
  try {
    //check is a user exist
    const user =
      (await Users.findOne({ email: req.body.email })) ||
      (await Users.findOne({ username: req.body.username }));
    if (user) {
      if (bcrypt.compareSync(req.body.password, user.password)) {
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        refreshTokens.push(refreshToken);
        res.status(200).json({
          status: "success",
          user,
          accessToken,
          refreshToken,
        });
      } else {
        res.status(400).json({
          status: "failed",
          message: "Incorrect password! please try again.",
        });
      }
    } else {
      res.status(403).json({
        status: "exist",
        message: "User does not exist!  Please register.",
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "error", message: "Connection Error!" });
  }
});

//logout
router.post("/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json({ message: "You logged out successfully." });
});

//get registered users
router.get("/", async (req, res) => {
  try {
    const users = await Users.find();
    if (users) {
      res.status(200).json(users);
    } else {
      res.status(404).json({ status: "not-found", message: "No user found!" });
    }
  } catch (err) {
    res.status(500).json({ status: "error", message: "Connection Error!" });
  }
});

//get a user
router.get("/:id", async (req, res) => {
  try {
    const user = await Users.findById(req.params.id);
    if (user) {
      res.status(200).json(user);
    } else {
      res.status(404).json({ status: "not-found", message: "User found!" });
    }
  } catch (err) {
    res.status(500).json({ status: "error", message: "Connection Error!" });
  }
});

//edit a user
router.put("/:id", async (req, res) => {
  if (req.body.userId === req.params.id) {
    try {
      const findUser = await Users.findById(req.params.id);
      if (findUser) {
        const user = await Users.findByIdAndUpdate(req.params.id, {
          $set: req.body,
        });
        res.status(200).json({
          status: "success",
          message: "Account updated successfully",
        });
      } else {
        res
          .status(404)
          .json({ status: "Not-found", message: "User not founnd!" });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ status: "error", message: "Connection Error!" });
    }
  } else {
    res
      .status(403)
      .json({ status: "failed", message: "You cannot perform this action!" });
  }
});

//edit a user by admin
router.put("/edit-user/:id", verify, async (req, res) => {
  try {
    const findAdmin = req.user.isAdmin;
    if (findAdmin) {
      const user = await Users.findByIdAndUpdate(req.params.id, {
        $set: req.body,
      });
      res.status(200).json({
        status: "success",
        message: "Account updated successfully",
      });
    } else {
      res.status(404).json({
        status: "Not-allowed",
        message: "You cannot perform this operation!",
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "error", message: "Connection Error!" });
  }
});

//update user password
router.put("/:id/password-reset", verify, async (req, res) => {
  if (req.user.id === req.params.id || req.user.isAdmin) {
    try {
      const findUser = await Users.findById(req.params.id);
      if (bcrypt.compareSync(req.body.password, findUser.password)) {
        if (req.body.password) {
          const salt = await bcrypt.genSalt(10);
          req.body.password = await bcrypt.hash(req.body.password, salt);
        }
        const user = await Users.findByIdAndUpdate(
          req.params.id,
          { $set: req.body },
          { new: true }
        );
        res.status(200).json({
          status: "success",
          message: "Password updated successfully",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ status: "error", message: "Connection Error!" });
    }
  } else {
    res
      .status(403)
      .json({ status: "failed", message: "You cannot perform this action!" });
  }
});

//delete  a user by an admin
router.delete("/delete/:id", verify, async (req, res) => {
  try {
    const findAdmin = req.user.isAdmin;
    if (findAdmin) {
      const user = await Users.findByIdAndDelete(req.params.id);
      if (user) {
        res.status(200).json("User deleted successfully");
      } else {
        res.status(404).json("User not found! User might be deleted in previous actions");
      }
    }else{
      res.status(401).json("You are not authorized")
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "error", message: "Connection Error!" });
  }
});

module.exports = router;
