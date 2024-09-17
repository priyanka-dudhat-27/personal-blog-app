import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/userModel.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";


const generateAccessAndRefreshToken=async(userId)=>{
  try {
    const user=await User.findById(userId);
    const accessToken=user.generateAccessToken()
    const refreshToken=user.generateRefreshToken()

    user.refreshToken=refreshToken
    await user.save({validateBeforeSave:false})

    return  {accessToken,refreshToken}

  } catch (error) {
    throw new ApiError(500,"Something went wrong while generating refresh and access token")
  }
}

const registerUser = asyncHandler(async (req, res) => {
  const { fullname, email, username, password} = req.body;

  // Validate required fields
  if (
    [fullname, email, username, password].some(
      (field) => !field || field.trim() === ""
    ) 
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // Check if user already exists
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }

  // Create new user
  const user = await User.create({
    fullname,
    email,
    password,
    username: username.toLowerCase(),
  });

  // Fetch the created user without sensitive information
  const createdUser = await User.findById(user._id).select("-password -refreshToken");

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // Send response
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully"));
});


// login
const loginUser=asyncHandler(async(req,res)=>{
    
    console.log(req.body);

    const {email,username,password}=req.body;

    if (!username && !email) {
      throw new ApiError(400, "username or email is required");
  }

    const user=await User.findOne({
      $or:[{username},{email}]
    })

    if(!user){
      throw new ApiError(404,"user does not exist")
    }

    const isPasswordValid=await user.isPasswordCorrect(password)

    if(!isPasswordValid){
      throw new ApiError(401,"Invalid password")
    }

    const {accessToken,refreshToken} = await generateAccessAndRefreshToken(user._id)

    const loggedInUser=await User.findById(user._id).select("-password -refreshToken")

    //cookies
    const options={
      httpOnly: true,
      secure:true
    }

    return res.status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
      new ApiResponse(200,
        {
          user:loggedInUser,accessToken,refreshToken
        },
        "user Logged in successfully"
      )
    )

})

// logout 
const logoutUser=asyncHandler(async(req,res)=>{
     User.findByIdAndUpdate(
      req.user._id,
      {
          $unset:{
            refreshToken:1 //this removes the field from document
          }
      },
      {
        new:true
      }
     )

     const options={
      httpOnly:true,
      secure:true
     }

     return res
     .status(200)
     .clearCookie("accessToken",options)
     .clearCookie("refreshToken",options)
     .json(new ApiResponse(200,{},"User Loggedout successfully"))
})

// refresh access Token api
const refreshAccessToken =asyncHandler(async(req,res)=>{
    const incomingRefreshToken=req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
      throw new ApiError(401,"Unauthorized request")
    }

   try {
     const decodedToken=jwt.verify(
       incomingRefreshToken,
       process.env.REFRESH_TOKEN_SECRET
     )
 
     const user=await User.findById(decodedToken?._id)
 
     if(!user){
       throw new ApiError(401,"Invalid refresh token")
     }
 
     if(incomingRefreshToken !== user?.refreshToken){
       throw new ApiError(401,"Refresh token is expired or used")
     }
 
     const options={
       httpOnly:true,
       secure:true
     }
 
     const {accessToken,newRefreshToken}=await generateAccessAndRefreshToken(user._id)
 
     return res.status(200)
     .cookie("accessToken",accessToken)
     .cookie("refreshToken",newRefreshToken)
     .json(
       200,
       {accessToken,refreshToken:newRefreshToken,message:"Access Token Refreshed"},
     )
   } catch (error) {
      throw new ApiError(401,error?.message || "Invalid Refresh Token")
   }

  })

  

  
  
export { 
  registerUser ,
  loginUser,
  logoutUser,
  refreshAccessToken,

}
