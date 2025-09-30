import { generateToken } from "../lib/utils.js";
import User from "../models/User.js";
import bcrypt from 'bcryptjs';
import cloudinary from "../lib/cloudinary.js";


// sign up
export const signup = async(req, res)=>{
    try {
        const {fullName, email, password, bio} = req.body;
        if(!fullName || !email || !password || !bio){
            return res.json({success: false, message: "Missing Details"});
        }

        const user = await User.findOne({email});
        if(user) {
            return res.json({success: false, message: "Account already exists"});            
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            fullName,
            email,
            password: hashedPassword,
            bio
        });

        const token = generateToken(newUser._id);

        res.json({success: true, user: newUser, token, message: "Account created successfully"});
    }
    catch(error){
        console.log(error);
        res.json({success: false, message: error.message});
    }
}

// login
export const login = async(req, res)=>{
    try {
        const { email, password } = req.body;
        const user = await User.findOne({email});

        if(!user) {
            return res.json({success: false, message: "Account doesn't exist"});
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if(!isPasswordCorrect) {
            return res.json({success: false, message: "Invalid credentials"});
        }
        const token = generateToken(user._id);

        res.json({success: true, user, token, message: "Login successful"});
    }
    catch(error){
        console.log(error);
        res.json({success: false, message: error.message});
    }
}

// authentication
export const checkAuth = (req, res) => {
    res.json({success: true, user: req.user});
}

// update
export const update = async(req, res)=>{
    try {
        const { profilePic, fullName, bio } = req.body;
        const userId = req.user._id;
        let updatedUser;

        if(!profilePic) {
            updatedUser = await User.findByIdAndUpdate(userId, {bio, fullName}, {new: true});
        }else {
            const upload = await cloudinary.uploader.upload(profilePic);
            updatedUser = await User.findByIdAndUpdate(userId, {profilePic: upload.secure_url, bio, fullName}, {new: true});
        }

        res.json({success: true, user: updatedUser, message: "Update successful"});
    }
    catch(error){
        console.log(error);
        res.json({success: false, message: error.message});
    }
}