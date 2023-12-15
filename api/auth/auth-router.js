// [ ] 2C - Endpoints - Authentication will be implemented using JSON Web Tokens.

const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs"); // i think we need this
const jwt = require("jsonwebtoken"); // i think we need this
const User = require("../users/users-model");

// [ ] 8. POST /api/auth/register
router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body;
  const { role_name } = req;
  const hash = bcrypt.hashSync(password, 8);

  User.add({ username, password: hash, role_name })
    .then((newUser) => {
      res.status(201).json(newUser);
    })
    .catch(next);
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

// [ ] 9. POST /api/auth/login
router.post("/login", checkUsernameExists, (req, res, next) => {
  // if password is correct, the token must be returned
  // else return invalid credentials

  const { username, password } = req.body;

  if (bcrypt.compareSync(password, req.user.password)) {
    const token = buildToken(req.user);
    res.status(200).json({
      message: `${username} is back!`,
      token,
    });
  } else {
    next({ status: 401, message: "Invalid credentials" });
  }

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
