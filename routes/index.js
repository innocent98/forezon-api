const router = require("express").Router();

const userRoute = require("./users");

router.use("/api/user", userRoute);

module.exports = router;
