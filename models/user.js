const { createHmac, randomBytes, hash }  = require("crypto");

const { Schema, model } = require("mongoose");

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
        type:String
    },
    password:{
        type: String
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
}, {timestamps: true}
);

//Hashing the users password before saving
userSchema.pre("save", function (next) {
    const user = this;
  
    if (!user.isModified("password")) return;
  
    const salt = randomBytes(16).toString(); //Random bits

    const hashedPassword = createHmac("sha256", salt) //Algorithm
      .update(user.password) //What to hash
      .digest("hex"); //return in hex format
  
    this.salt = salt;
    this.password = hashedPassword;
  
    next();
  });

const User = model('user', userSchema);

module.exports = User;