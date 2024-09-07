const User = require("../models/User");

exports.createNewUser = async (data) => {
    const user = await User.create(data);
    return user;
}

exports.getUserByEmail = async (email) => {
    const user = await User.findOne({ email });
    return user;
}

exports.getUserById = async (userId) => {
    const user = await User.findOne({ _id: userId }, "-password");
    return user;
}

