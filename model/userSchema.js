import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    accessToken:String, 
    refreshToken:String,
    googleId:String, 
    userName:String, 
    email:String, 
    endDate:Number, 
    isANewUser: {
        type:Boolean, 
        default:true
    }, 
    userRating : {
        type:Number, 
        default:1
    },
    buttonCounts: {
        type: Number,
        default: 0
    },
    totalCount: {
        type: Number,
        default: 60
    }
},{timestamps:true});

const userdb = new mongoose.model("replai", userSchema);

export default userdb;