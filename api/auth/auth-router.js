// [ ] 2C - Endpoints - Authentication will be implemented using JSON Web Tokens.

const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const jwt = require("jsonwebtoken"); // i think we need this
const { JWT_SECRET } = require("../secrets"); // use this secret!

// [ ] 8. POST /api/auth/register
router.post("/register", validateRoleName, (req, res, next) => {
  res.json({ message: "register connected" });

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
  res.json({ message: "login connected" });
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

module.exports = router;
