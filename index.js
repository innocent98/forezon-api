const express = require("express");
const app = express();
const cors = require("cors");
const morgan = require("morgan");
const helmet = require("helmet");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const router = require("./routes/index");
const path = require("path")

dotenv.config();

//create database connection
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Database  connected"))
  .catch((err) => console.log(err));

//middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());
app.use(morgan("common"));
app.use(helmet());

//user router
app.use(router);

//heroku
app.use(express.static(path.join(__dirname, "/client/build")));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, "client", "build", 'index.html'));
});

//server connection
app.listen(process.env.PORT || 5002, () => {
  console.log("server started");
});
