/*const mongoose=require("mongoose");
const UserDetailSchema = new mongoose.Schema({

username:{type:String,unique:true},
email:{type:String,unique:true},
password:String,
otp:String,
resetTokenExpiration:Date,
Cloned_Audio:[
    {
        fileName: String,
        fileUri: String,
        CreatedAt:{
            type: Date,
            default: Date.now
        }
    }]
Generated_Audio:[
     {
        fileName: String,
        fileUri: String,
        CreatedAt:{
            type: Date,
            default: Date.now
        }}
]},{
    collection:"UserInfo"

})
mongoose.model("UserInfo",UserDetailSchema);*/


const mongoose = require("mongoose");

const AudioSchema = new mongoose.Schema({
  fileName: String,
  fileUri: String,
  publicId: String,
  duration: Number,  // optional
  createdAt: { type: Date, default: Date.now },
  metadata: Object   // optional for extra info
});

const UserDetailSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String,
  otp: String,
  resetTokenExpiration: Date,
 generatedAudio: {
  type: [AudioSchema],
  default: []
 },
 clonedAudio: {
  type: [AudioSchema],
  default: []
 }
}, {
  collection: "UserInfo"
});

mongoose.model("UserInfo", UserDetailSchema);