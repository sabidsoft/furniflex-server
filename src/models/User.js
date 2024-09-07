const { Schema, model } = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new Schema({
    firstName: {
        type: String,
        default: ''
    },
    lastName: {
        type: String,
        default: ''
    },
    email: {
        type: String,
        trim: true,
        unique: true,
        lowercase: true,
        required: [true, "Email is required"],
        validate: {
            validator: (value) => {
                const pattern = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
                const isEmail = pattern.test(value);
                return isEmail;
            },
            message: "Invalid email address"
        }
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        minLength: [6, "Password should be at least 6 characters long."],
    },
}, {
    timestamps: true
})

//  Hashing password before saving
userSchema.pre("save", function (next) {
    this.password = bcrypt.hashSync(this.password, 10);
    next();
})

// comparing password
userSchema.methods.comparePassword = function (password, hashPassword) {
    const isMatchedPassword = bcrypt.compareSync(password, hashPassword);
    return isMatchedPassword;
}

const User = model("User", userSchema);

module.exports = User;