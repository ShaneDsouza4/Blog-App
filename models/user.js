const { createHmac, randomBytes, hash }  = require("crypto");

const { Schema, Model } = require("mongoose");

const userSchema = new Schema({
    fullName:{
        type: String,
        required: true
    },
    email:{
        type: String,
        required: true,
        unique: true
    },
    salt:{
        type:String,
        required: true
    },
    password:{
        type: String,
        required: true
    },
    profileImageURL:{
        type: String,
        default: "/images/default.png"
    },
    role:{
        type: String,
        enum: ["USER", "ADMIN"],
        default: "USER"
    }
}, {timestamps: true});

userSchema.pre('save', function (next){
    const user = this; //this points to user

    if(!user.isModified('password')) return;

    const salt = randomBytes(16).toString(); //Random string
    const hashedPassword = createHmac('sha256', salt) //Algorithm, key
    .update(user.password) //Update user's plain password
    .digest('hex'); //return in hex format

    this.salt = salt;
    this.password = hashedPassword;

    next();
})

const User = model('user', userSchema);

module.exports = User;