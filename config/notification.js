const nodemailer = require("nodemailer");
const dotenv = require("dotenv");

dotenv.config();

const transport = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

module.exports.sendConfirmationEmail = async (username, amount) => {
  console.log("Check");
  const message = {
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_USER,
    subject: "Notification",
    html: `<h1>Notification</h1>
          <h2>Hello</h2>
          <p>This user ${username} just made a deposit of ${amount}, kindly confirm.
          </p>
          </div>`,
  };

  await new Promise((resolve, reject) => {
    transport.sendMail(message, (err, info) => {
      if (err) {
        console.log(err);
      } else {
        console.log(info);
      }
    });
  });
};

module.exports.sendWithdrawEmail = async (username, amount) => {
  console.log("Check");
  const message = {
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_USER,
    subject: "Notification",
    html: `<h1>Notification</h1>
          <h2>Hello</h2>
          <p>This user ${username} just made a withdrawal request of ${amount}, kindly confirm.
          </p>
          </div>`,
  };

  await new Promise((resolve, reject) => {
    transport.sendMail(message, (err, info) => {
      if (err) {
        console.log(err);
      } else {
        console.log(info);
      }
    });
  });
};
