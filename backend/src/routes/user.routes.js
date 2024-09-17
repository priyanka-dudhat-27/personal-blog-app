import { Router } from "express";
import { loginUser, logoutUser, registerUser,refreshAccessToken} from "../controllers/user.controllers.js";
import jwt from "jsonwebtoken";
import { verifyJWT } from "../middlewares/auth.middlware.js";


const router = Router();

router.route("/register").post(registerUser);

router.route("/login").post(loginUser)

// // secure routes
router.route("/logout").post(verifyJWT,logoutUser)
router.route("/refreshAccessToken").post(refreshAccessToken)


export default router;

