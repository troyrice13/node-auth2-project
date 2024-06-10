const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets");
const Users = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Token invalid" });
    }
    req.decodedJwt = decoded;
    next();
  });
}

const only = (role_name) => (req, res, next) => {
  if (!req.decodedJwt || req.decodedJwt.role_name !== role_name) {
    return res.status(403).json({ message: "This is not for you" });
  }
  next();
}

const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body;
  const user = await Users.findBy({ username }).first();
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  next();
}

const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;
  if (!role_name || !role_name.trim()) {
    req.role_name = 'student';
    return next();
  }
  if (role_name.trim() === 'admin') {
    return res.status(422).json({ message: "Role name can not be admin" });
  }
  if (role_name.trim().length > 32) {
    return res.status(422).json({ message: "Role name can not be longer than 32 chars" });
  }
  req.role_name = role_name.trim();
  next();
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
