const router = require("express").Router();
const { signup, login, getUser } = require("../controllers/user.controller");
const verifyToken = require("../middlewares/verifyToken");

router.post("/signup", signup);
router.post("/login", login);
router.get("/", verifyToken, getUser);

module.exports = router;