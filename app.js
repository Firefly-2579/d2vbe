const express = require("express");
const app = express();
const mongoose=require("mongoose");
app.use(express.json());
const bcrypt=require("bcryptjs");
const bcrypt1=require("bcrypt");
const jwt=require('jsonwebtoken');
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const ffmpegPath = require("@ffmpeg-installer/ffmpeg").path;
const ffmpeg = require("fluent-ffmpeg");
const FormData = require("form-data");
const axios = require("axios");

const pdfParse = require("pdf-parse");
const textract = require("textract");
const mammoth = require("mammoth");
const { promise } = require("bcrypt/promises");
require("dotenv").config();


ffmpeg.setFfmpegPath(ffmpegPath);

const tempOtpStore = {};
const verifyTokenAndGetUser = async (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ email: decoded.email });
    return user;
  } catch (err) {
    console.error("Error verifying token:", err);
    return null;
  }
};

//############## MONGODB CONFIGURATION ##################
// mongodb url
const mongoUrl= process.env.MONGODB_URL;
const JWT_SECRET= process.env.JWT_SECRET;
// code to connect to mongodb
mongoose
.connect(mongoUrl)
.then(()=>{
  console.log("Database Connected");
  })
  .catch((e)=>{
  console.log(e);
});
//importing schema
require('./UserDetails')
const User = mongoose.model("UserInfo");
app.get("/",(req,res)=>{
res.send({status:"started"});
});

//####### CLOUDINARY CONFIGURATION ###########
const cloudinary = require("cloudinary").v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

//########## RESTFUL APIS ##################

//send-otp
app.post('/send-otp', async (req, res) => {
  
  const { email } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ status: 'error', message: 'User already exists with this email' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 mins

    const hashedOtp = await bcrypt.hash(otp, 10);

    // Store in memory
    tempOtpStore[email] = { hashedOtp, expiresAt };

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'OTP for Signup Verification',
      text: `Your OTP for signup is: ${otp}`,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error('Email sending error:', error);
        return res.status(500).json({ status: 'error', message: 'Failed to send OTP email' });
      }

      return res.json({ status: 'success', message: 'OTP sent to email' });
    });
  } catch (err) {
    console.error('Send OTP error:', err);
    return res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

//verify-for-email
app.post('/verify-for-email',async (req, res) => {
  const { email, otp } = req.body;

  const record = tempOtpStore[email];

  if (!record) {
    return res.status(400).json({ status: 'error', message: 'OTP not sent or expired' });
  }

  if (Date.now() > record.expiresAt) {
    delete tempOtpStore[email];
    return res.status(400).json({ status: 'error', message: 'OTP expired' });
  }

  const isMatch = await bcrypt.compare(otp.trim(), record.hashedOtp);
  if (!isMatch) {
    return res.status(400).json({ status: 'error', message: 'Invalid OTP' });
  }

  // OTP is valid, cleanup
  delete tempOtpStore[email];
  return res.json({ status: 'success', message: 'OTP verified successfully' });
});

//signup api    //1
app.post("/signup",async (req,res) =>{
    const {username,email,password}=req.body;             //values from application

    const oldUser=await User.findOne({email:email})        // checking if user already exists
    if(oldUser){
        return res.send({data:"User already exists!"});
    }

  const encryptedPassword= await bcrypt.hash(password,10);  // registering user

 try{
  await User.create({
    username: username,
    email:email,
    password: encryptedPassword,
    })
    res.send({status:"ok",data:"User created"})
    } catch (error) {
    res.send({status:"error",data:error});
 }

});

//signin api   //2
app.post("/signin-user",async(req,res)=>{
 const{identifier, password}=req.body;

 let oldUser;
 if(identifier.includes('@')){
  oldUser =await User.findOne({email: identifier});
 } else{
  oldUser =await User.findOne({username: identifier});
 }

 if(!oldUser){
   return res.send({ status: "error", message:"User doesnot exist!!"});
 }

 const isPasswordValid = await bcrypt.compare(password, oldUser.password);

 if(!isPasswordValid) {
  return res.send({ status: "error", message: "Invalid credentials" }); 
 }

 const token=jwt.sign({email: oldUser.email,  userId: oldUser._id},JWT_SECRET);
   
   if(res.status(201)){
   return res.send({status:"ok",data:token});
   } else {
   return res.send({error:"error"});
   }
  }
);

//userdata API     //3
app.post("/userdata",async(req,res)=>{
      const {token}=req.body;
      try {
       

         const decoded = jwt.verify(token,JWT_SECRET);
        const useremail=decoded.email;

       
     const userData = await User.findOne({ email: useremail });

     if (!userData) {
         return res.status(404).send({ error: "User not found" });
     }

     return res.status(200).send({ status: "ok", data: userData });

 } catch (error) {
     return res.status(401).send({ error: "Invalid token" });
 }

});

//updateprofile api   //4
app.post('/update-profile', async (req, res) => {
 try{
  const{token, username} = req.body;
  const user = await verifyTokenAndGetUser(token);
  if (!user){ return res.status(401).json({ success: false, message: 'Unauthorized'});
  }
  const trimmed = username.trim();
    const usernameRegex = /^(?=.{3,20}$)(?=.*[A-Za-z])[A-Za-z0-9_]+$/;
    if (!usernameRegex.test(trimmed)) {
      return res.status(400).json({
        success: false,
        message: "Username must be 3–20 chars, only letters, numbers, underscores"
      });
    }
    const existingUser = await User.findOne({ username: trimmed, _id: { $ne: user._id } });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Username already exists" });
    }
  user.username = trimmed;
  await user.save();
  res.json({ success: true, message: 'Username updated successfully' });
  } catch (err) {
    console.error("Server Error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});


//resets-password api  //5
app.post('/resets-password', async (req, res) => {
  try {
    const { token, oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Old and new passwords are required.' });
    }

    const user = await verifyTokenAndGetUser(token);
    if (!user) return res.status(401).json({ success: false, message: 'Unauthorized' });

    const isMatch = await bcrypt1.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Old password is incorrect.' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = null;
    await user.save();

    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('Error in /resets-password:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// verify-OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    if (!email || !otp) {
      return res.status(400).json({ status: 'error', message: 'Email and OTP are required.' });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found.' });
    }

    if (!user.otp) {
      return res.status(400).json({ status: 'error', message: 'OTP has already been used or was not generated.' });
    }

    const trimmedOtp = otp.trim();

    if (new Date() > user.resetTokenExpiration) {                   // Check if OTP has expired before comparing it
      return res.status(400).json({ status: 'error', message: 'OTP has expired. Please repeat the process.' });
    }

    const isMatch = await bcrypt.compare(trimmedOtp, user.otp)
    if (!isMatch) {
      console.log('OTP mismatch:', user.otp, '!=', trimmedOtp);
      return res.status(400).json({ status: 'error', message: 'Invalid code. Please try again.' });
    }

    user.otp = null;                   // if OTP verified successfully
    user.resetTokenExpiration = null;
    await user.save();

    return res.json({ status: 'success', message: 'OTP verified successfully.' });
  } catch (error) {
    console.error('Error in /verify-otp:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error.' });
  }
});


// forgot-password api        //7
app.post('/forgot-password',async (req,res) => {
  const {email} = req.body;

  try{
    const user = await User.findOne({email});
    if(!user){
     return res.status(404).json({status:'error',message:'Email not registered!'});
    }

    const otp= Math.floor(100000 +Math.random() * 900000);
    const resetTokenExpiration= new Date(Date.now() + 10 * 60 * 1000);

    console.log('Generated OTP',otp);
    console.log('Reset Token Expiration',resetTokenExpiration);

    const hashedOtp = await bcrypt.hash(otp.toString(), 10);
    user.otp = hashedOtp;                                   // Save OTP in the user document
    user.resetTokenExpiration = resetTokenExpiration; // OTP expires in 10 min
    
    await user.save();
    
    const transporter = nodemailer.createTransport({
      service: "gmail",  
      auth: {
        user: process.env.EMAIL_USER,                    
        pass: process.env.EMAIL_PASS,                      
      },
      debug: true,                                        // Enable debugging
  logger: true,                                           // Log connection details
    });
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject:'Password Reset OTP',
      text:`Your OTP for password reset is: ${otp}`,
    };

    transporter.sendMail(mailOptions,(error)=>{
      if(error){
        console.error('error sending email:',error);
        return res.status(500).send({status : 'error', message: 'Error sending OTP email'});  
      }
      res.json({status: 'success', message: 'OTP send to your email'});
    });

  } catch (error){
   console.error('Error in forget-password route', error);
   res.status(500).send({ status: 'error', message: 'Internal server error'});

  }
});

// reset-password API     //8
app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).send({
      status: 'error',
      message: 'Email and new password are required.'
    });
  }

  const strongPasswordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/;
  if (!strongPasswordRegex.test(newPassword)) {
    return res.status(400).send({
      status: 'error',
      message: 'Password must be at least 8 characters long and include uppercase, lowercase, special character and number.'
    });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send({
        status: 'error',
        message: 'User not found!'
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = null;
    user.resetToken = null;
    user.resetTokenExpiration = null;

    await user.save();

    return res.send({
      status: 'success',
      message: 'Password reset successfully'
    });

  } catch (error) {
    console.error('Error in reset-password route:', error);
    return res.status(500).send({
      status: 'error',
      message: 'Internal server error'
    });
  }
});


// save cloned_audio API

const upload = multer({ dest: "uploads/" });

app.post('/save-cloned-audio', upload.single("file"), async (req,res) => {
  try {
    const { token, fileName} = req.body;
    console.log("[CLONED AUDIO LOG] fileName:", fileName);
    console.log("[CLONED AUDIO LOG] uploaded file path:", req.file.path);

    const user = await verifyTokenAndGetUser(token);
    if (!user) return res.status(401).json({ success: false, message: "unauthorized" });

    const timestamp = Date.now();
    const ext = fileName.split(".").pop();
    const baseName = fileName.replace(/\.[^/.]+$/, "");
    const uniqueFileName = `${baseName}_${timestamp}.${ext}`;

    // upload cloned audio file to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: "video",   // required for audio
      folder: "cloned_audio",    // upload into your Cloudinary folder
      public_id: uniqueFileName.replace(/\.[^/.]+$/,""),
    });

  
    const newAudio = {
      fileName: uniqueFileName,
      fileUri: result.secure_url,   //  use Cloudinary URL instead of local fileUri
      publicId: result.public_id,  // store Cloudinary public_id for later delete if needed
    };

    console.log("Saving file:", newAudio.fileUri);

    if (!user.clonedAudio.some((a) => a.fileUri === newAudio.fileUri)) {
      user.clonedAudio.push(newAudio);
      await user.save();
    }

    fs.unlink(req.file.path, (err) => {
     if (err) console.warn("Temp file cleanup failed:", err);
    });
    
    const savedAudio = user.clonedAudio[user.clonedAudio.length - 1];

    res.json({ success: true, data: savedAudio, message: "Audio saved successfully" });
  } catch (error) {
    console.error("Error saving audio", error);
    res.status(500).json({ success: false, message: error.message || "Failed to save audio" });
  }
});

//save generated_audio API
app.post("/save-generated-audio", upload.single("file"), async (req, res) => {
  try {
    const { token, fileName} = req.body;
    console.log("[SAVED AUDIO LOG] fileName:", fileName);
    console.log("[SAVED AUDIO LOG] uploaded file path:", req.file.path);

    const user = await verifyTokenAndGetUser(token);
    if (!user) return res.status(401).json({ success: false, message: "unauthorized" });

    const timestamp = Date.now();                             
    const ext = fileName.split(".").pop();                    
    const baseName = fileName.replace(/\.[^/.]+$/, "");       
    const uniqueFileName = `${baseName}_${timestamp}.${ext}`;

    //upload generated audio to cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: "video",   // required for audio
      folder: "generated_audio",    // upload into your Cloudinary folder
      public_id: uniqueFileName.replace(/\.[^/.]+$/,""),
    });

    const newAudio = {
      fileName: uniqueFileName,
      fileUri: result.secure_url,
      publicId: result.public_id,
    };

    console.log("Saving file:", newAudio.fileUri);

    if (!user.generatedAudio.some(a => a.fileUri === newAudio.fileUri)) {
     user.generatedAudio.push(newAudio);
     await user.save();
    }

    fs.unlink(req.file.path, (err) => {
     if (err) console.warn("Temp file cleanup failed:", err);
    });

    const savedAudio = user.generatedAudio[user.generatedAudio.length-1];

    res.json({ success: true,data: savedAudio, message: "Audio saved successfully" });
   } catch (error) {
    console.error("Error saving audio", error);
    res.status(500).json({ success: false, message: error.message || "Failed to save audio" });
  }
});


// delete audio file(generated or cloned)

app.delete("/delete-audio/:userId/:type/:id", async (req, res) => {
  
  console.log("DELETE request params:", req.params);
  try {
    const { userId, type, id } = req.params; 
    const User = mongoose.model("UserInfo");

    const user = await User.findById(userId);      // to fetch the user
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    let audioArray = type === "generated" ? user.generatedAudio : user.clonedAudio;   // to choose which array to delete from

    const audioIndex = audioArray.findIndex((a) => a._id.toString() === id);  // find audio by id
    if (audioIndex === -1) {
      return res.status(404).json({ success: false, message: "Audio not found" });
    }

    const removedAudio = audioArray.splice(audioIndex, 1)[0];                // remove from database array
    await user.save();

    if(removedAudio.publicId){
      const result = await cloudinary.uploader.destroy(removedAudio.publicId, { resource_type: "video", });
      console.log("Cloudinary delete result:", result);
    }

    res.json({ success: true, message: "Audio deleted successfully" });

  } catch (error) {
    console.error("Error deleting audio:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Delete-account API
app.post('/delete-account', async (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log("Decoded token:", decoded);
    
    const userId = decoded.userId;
    console.log("Decoded userId:", userId);

    // Delete user document
    const user = await User.findById(userId);
    if(!user){
      return res.status(404).json({ success : false, message: "User not found"});
    }

    const publicIds = [
      ...user.generatedAudio.map(audio => audio.publicId),
      ...user.clonedAudio.map(audio => audio.publicId),
    ].filter(Boolean);

    if(publicIds.length > 0){
      await Promise.all(
        publicIds.map(id =>
          cloudinary.uploader
          .destroy(id, { resource_type: "video" })
          .then(() => console.log(`Deleted file: ${id}`))
          .catch(err => console.error(`Failed to delete ${id}`, err))
        )
      );
    }

    const deletedUser = await User.findByIdAndDelete(userId);
    console.log("Deleted user:", deletedUser);

    return res.json({ success: true, message: 'Account deleted successfully' });
  } catch (error) {
    
    if(error.name === "TokenExpiredError"){
     return res.status(401).json({ success : false, message: "Session expired. Please signin again before deleting account"}); 
    }

     if(error.name === "JsonWebTokenError"){
     return res.status(401).json({ success : false, message: "Invalid authentication token"}); 
    }   

    console.error(error);
    return res.status(500).json({ success: false, message: 'Invalid token or server error' });
  }
});

 //Getting user audios(generated + cloned)
  app.post("/get-user-audio", async (req, res) => {
  const { token } = req.body;
  try {
    const user = await verifyTokenAndGetUser(token);
    if (!user) return res.status(401).json({ success: false, message: "Unauthorized" });

    res.json({
      success: true,
      userId: user._id.toString(),
      generatedAudio: user.generatedAudio || [],
      clonedAudio: user.clonedAudio || [],
    });
    
  } catch (err) {
    console.error("Error fetching audio:", err);
    res.status(500).json({ success: false, message: "Failed to fetch audio" });
  }
}); 
//################# FAST APIS #############################

const model1Url = process.env.MODEL1_URL;
const model2Url = process.env.MODEL2_URL;
const model3Url = process.env.MODEL3_URL;

const diskUpload = multer({ dest: "uploads/" });

//xtts_cm_model

app.post("/process-voice", diskUpload.single("speaker_wav"), async (req, res) => {
  if (!req.file) return res.status(400).send("No file uploaded");

  const inputPath = req.file.path;
  const outputPath = `converted_${Date.now()}.wav`;
  const text = req.body.text;

  ffmpeg(inputPath)                                 // convert audio first
    .outputOptions([
      "-ar 22050",
      "-ac 1",
      "-acodec pcm_s16le",
    ])
    .toFormat("wav")
    .on("end", async () => {
      console.log("Conversion complete:", outputPath);

      try {
        const form = new FormData();                // create form data to send to FastAPI
        form.append("speaker_wav", fs.createReadStream(outputPath));
        form.append("text", text);

        const response = await axios.post(`${model1Url}/synthesize`, form, {
          headers: form.getHeaders(),
          responseType: "stream",                   // to get back audio stream
        });

        res.setHeader("Content-Type", "audio/wav");  // to send cloned audio back to frontend
        response.data.pipe(res);

        response.data.on("end", () => {               // to cleanup temporary files
          fs.unlinkSync(inputPath);
          fs.unlinkSync(outputPath);
        });

      } catch (error) {
        console.error("Error contacting FastAPI:", error);
        res.status(500).send("Synthesis failed");
        fs.unlinkSync(inputPath);
        fs.unlinkSync(outputPath);
      }
    })
    .on("error", (err) => {
      console.error("FFmpeg error:", err);
      res.status(500).send("Audio conversion failed");
      fs.unlinkSync(inputPath);
    })
    .save(outputPath);
});

//xtts_finetuned_model_1

const memoryUpload = multer({ storage: multer.memoryStorage() });

async function extractText(buffer, originalname) {                   // extract text from buffer & limit to 200 words
    const ext = originalname.split(".").pop().toLowerCase();
    let text = "";

    if (ext === "pdf") {
        const data = await pdfParse(buffer);
        text = data.text;
    } else if (ext === "txt") {
        text = buffer.toString("utf-8");
    } else if (ext === "doc" || ext === "docx") {
        text = await new Promise((resolve, reject) => {
            textract.fromBufferWithName(originalname, buffer, (err, text) => {
                if (err) reject(err);
                else resolve(text);
            });
        });
    } else {
        throw new Error("Unsupported file type");
    }
   
    text = text.trim();
    const maxChars = 150;
    if (text.length <= maxChars) return text;
    let chunk = text.slice(0, maxChars);
    let cut = Math.max(chunk.lastIndexOf("."), chunk.lastIndexOf("?"), chunk.lastIndexOf("!"));
    if (cut > 50) { 
        return chunk.slice(0, cut + 1);
    }
    let spaceCut = chunk.lastIndexOf(" ");
    return spaceCut > 0 ? chunk.slice(0, spaceCut) : chunk;
}

app.post("/process-doc-voice1", memoryUpload.single("file"), async (req, res) => {
  console.log("Received file:", req.file);
  
    try {
        if (!req.file) {
            return res.status(400).send("No file uploaded");
        }

        console.log("Starting text extraction...");                      // extract text directly from memory
        const extractedText = await extractText(req.file.buffer, req.file.originalname);
        console.log("Extraction complete, characters:", extractedText.length);
        console.log("Extraction complete, words:", extractedText.split(/\s+/).length);
       
        const form = new FormData();                                      // send text to FastAPI TTS
        form.append("text", extractedText);

        console.log("Sending text to FastAPI, length:", extractedText.length);
        
        const response = await axios.post(`${model2Url}/synthesize`, form, {
            headers: form.getHeaders(),
            responseType: "stream"
        });

        console.log("FastAPI responded, streaming audio back...");
       
        res.setHeader("Content-Type", "audio/wav");                        // return audio stream to client
        response.data.pipe(res);

    } catch (err) {
        console.error("Processing error:", err);
        res.status(500).send("Failed to process document");
    }
});

//xtts_finetuned_model_2
app.post("/process-doc-voice2", memoryUpload.single("file"), async (req, res) => {
  console.log("Received file:", req.file);
  
    try {
        if (!req.file) {
            return res.status(400).send("No file uploaded");
        }

        console.log("Starting text extraction...");
        const extractedText = await extractText(req.file.buffer, req.file.originalname);
        console.log("Extraction complete, characters:", extractedText.length);
        console.log("Extraction complete, words:", extractedText.split(/\s+/).length);
       
        const form = new FormData();
        form.append("text", extractedText);

        console.log("Sending text to FastAPI, length:", extractedText.length);
        
        const response = await axios.post(`${model3Url}/synthesize`, form, {
            headers: form.getHeaders(),
            responseType: "stream"
        });

        console.log("FastAPI responded, streaming audio back...");
      
        res.setHeader("Content-Type", "audio/wav");
        response.data.pipe(res);

    } catch (err) {
        console.error("Processing error:", err);
        res.status(500).send("Failed to process document");
    }
});

/* app.listen(3000,()=>{
    console.log("Node js server started");
})*/

app.get("/", (req, res) => {
  res.send("Backend running on Render");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Node.js server started on port ${PORT}`);
});

