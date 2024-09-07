const createError = require("http-errors");
const { generateToken } = require("../utils/generateToken");
const { successResponse } = require("../utils/response");
const { getUserByEmail, createNewUser } = require("../services/user.service");

exports.signup = async (req, res, next) => {
    try {
        const { firstName, lastName, email, password } = req.body;
        const emailValidationPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

        if (!email)
            throw createError(400, "Email is required.");

        if (!emailValidationPattern.test(email))
            throw createError(400, "Invalid email address.");

        if (!password)
            throw createError(400, "Password is required.");

        if (password.length < 6)
            throw createError(400, "Password should be at least 6 characters long.");

        if (password.length > 40)
            throw createError(400, "Password is too long.");

        const isUserExist = await getUserByEmail(email);

        if (isUserExist)
            throw createError(400, "User allready exist.");

        const user = await createNewUser({ firstName, lastName, email, password });

        const { password: pass, ...userInfoWithoutPassword } = user.toObject();

        const token = generateToken({ email }, process.env.JWT_SECRET_KEY, "1d");

        successResponse(res, {
            status: 200,
            message: "Sign up successfull.",
            payload: { user: userInfoWithoutPassword, token }
        })
    }
    catch (err) {
        next(err);
    }
}

exports.login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const emailValidationPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

        if (!email)
            throw createError(400, "Please provide your email address.");

        if (!emailValidationPattern.test(email))
            throw createError(400, "Invalid email address.");

        if (!password)
            throw createError(400, "Please provide your password.");

        const user = await getUserByEmail(email);

        if (!user)
            throw createError(400, "No user found. Please create an account first.");

        const isMatchedPassword = user.comparePassword(password, user.password);

        if (!isMatchedPassword)
            throw createError(400, "Your email or password isn't correct.");

        const { password: pass, ...userInfoWithoutPassword } = user.toObject();

        const token = generateToken({ email }, process.env.JWT_SECRET_KEY, "1d");

        successResponse(res, {
            status: 200,
            message: "Sign in successfull.",
            payload: { user: userInfoWithoutPassword, token }
        })
    }
    catch (err) {
        next(err);
    }
}

exports.getUser = async (req, res, next) => {
    try {
        const user = await getUserByEmail(req.user.email);

        if (!user)
            throw createError(404, "User not found.");

        successResponse(res, {
            status: 200,
            message: "User found successfully.",
            payload: { user }
        });
    }
    catch (err) {
        next(err);
    }
}