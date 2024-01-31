const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

// Initializes Passport and specifies to Passport that we're using a username and password.
function initializePassport(passport, getUserByUsername, getUserByID) {
  // Authenticates a user based on their username and password.
  const authenticateUser = async (username, password, done) => {
    const user = getUserByUsername(username);
    console.log("User Verification: ", user);
    if (!user) {
      // If no user is found, return false and a message saying so.
      return done(null, false, { message: "No user with that username" });
    }

    // If a user is found, try to match the password.
    try {
      if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
      }
      return done(null, false, { message: "Password incorrect" });
    } catch (error) {
      return done(error);
    }
  };

  // Use the local strategy with Passport.
  passport.use(
    new LocalStrategy(
      // Specify that the usernameField in the request body should be used as the username.
      { usernameField: "username" },
      // Provide a custom callback function for the LocalStrategy that calls the authenticateUser function.
      (username, password, done) => authenticateUser(username, password, done)
    )
  );

  /* serializeUser is used to decide which data of the user object should be stored in the session. 
  The result of the serializeUser method is attached to the session as req.session.passport.user = {} 
  Here, the user's id is stored in the session. 
  This helps in managing the amount of data that gets stored in the session. */
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  /* The key (user id in this case) returned from serializeUser is used here. 
  The data returned from deserializeUser method is attached to the request as req.user. 
  This function is used to retrieve the whole object via the session key. 
  This is typically used to get other user details, like email or username, from the stored session id. */
  passport.deserializeUser((id, done) => {
    const user = getUserByID(id);
    if (user) {
      done(null, user);
    } else {
      done(new Error("User not found"));
    }
  });

  /* The deserializeUser function is used to retrieve the user data from the session. 
  The key that is stored in the session by serializeUser is used to retrieve the full user data in deserializeUser. 
  In this case, serializeUser is storing the user's id in the session. 
  Then deserializeUser is using that id to get the full user object. 
  The user object returned by deserializeUser is attached to the request as req.user,
  so you can access it in your routes. 
  For example, if you want to access the logged-in user's username in a route, 
  you can use req.user.username. */
}

function isUserAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

function isUserNotAuthenticated(req, res, next) {
  if (!req.isAuthenticated()) return next();
  // User is authenticated, redirect to homepage.
  res.redirect("/");
}

module.exports = {
  initializePassport,
  isUserAuthenticated,
  isUserNotAuthenticated,
};
