const router = require("express").Router();
const bcrypt = require("bcrypt");
const Users = require("../models/Users");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

//jsonwebtoken
const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.JWT_KEY, (err, user) => {
      if (err) {
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

//login a user
router.post("/login", async (req, res) => {
  try {
    //check is a user exist
    const user =
      (await Users.findOne({ email: req.body.email })) ||
      (await Users.findOne({ username: req.body.username }));
    if (user) {
      if (bcrypt.compareSync(req.body.password, user.password)) {
        const accessToken = jwt.sign(
          { id: user.id, isAdmin: user.isAdmin },
          process.env.JWT_KEY,
          {
            expiresIn: "60s",
          }
        );
        res
          .status(200)
          .json({ status: "success", user: user, token: accessToken });
      } else {
        res.status(401).json({
          status: "failed",
          message: "Incorrect password! please try again.",
        });
      }
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

//get registered users
router.get("/", async (req, res) => {
  try {
    const users = await Users.find();
    if (users) {
      res.status(200).json({ status: "success", users: users });
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
      res.status(200).json({ status: "success", user: user });
    } else {
      res.status(404).json({ status: "not-found", message: "User found!" });
    }
  } catch (err) {
    res.status(500).json({ status: "error", message: "Connection Error!" });
  }
});

//edit a user
router.put("/:id", verify, async (req, res) => {
  if (req.user.id === req.params.id || req.user.isAdmin) {
    try {
      const findUser = await Users.findById(req.params.id);
      if (findUser) {
        const user = await Users.findByIdAndUpdate(
          req.params.id,
          { $set: req.body },
          { new: true }
        );
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

//delete  a user
router.delete("/:id", verify, async (req, res) => {
  if (req.user.id === req.params.id || req.user.isAdmin) {
    try {
      const findUser = await Users.findByIdAndDelete(req.params.id);
      if (findUser) {
        res.status(200).json({
          status: "success",
          message: "User deleted successfully",
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

module.exports = router;
