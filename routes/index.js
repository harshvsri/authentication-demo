const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const passport = require("passport");
const {
  initializePassport,
  isUserAuthenticated,
  isUserNotAuthenticated,
} = require("../middlewares/auth");

const users = [];

(async function createTestUser() {
  const hashedPassword = await bcrypt.hash("test", 10);
  users.push({
    id: Date.now().toString(),
    fullName: "Test User",
    email: "test@gmail.com",
    username: "test",
    password: hashedPassword,
  });
})();

/* Initializes Passport with a local strategy, 
using provided functions to find users by username and id. */
initializePassport(
  passport,
  (username) => users.find((user) => user.username === username),
  (id) => users.find((user) => user.id === id)
);

router.get("/", isUserAuthenticated, function (req, res, next) {
  res.render("index", { user: req.user });
});

router.get("/register", isUserNotAuthenticated, (req, res) => {
  res.render("register");
});

router.get("/login", isUserNotAuthenticated, (req, res) => {
  res.render("login");
});

router.post("/register", isUserNotAuthenticated, async (req, res) => {
  const { fullName, email, username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({
      id: Date.now().toString(),
      fullName,
      email,
      username,
      password: hashedPassword,
    });
    res.redirect("/login");
  } catch (error) {
    res.redirect("/register");
  }
});

router.post(
  "/login",
  isUserNotAuthenticated,
  // Use Passport's local strategy for authentication and flash messages for errors.
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

router.post("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/login");
  });
});

module.exports = router;
