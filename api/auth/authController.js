require("dotenv").config()

const { dynamoDB } = require('../../config/awsConfig');
const { UpdateItemCommand,PutItemCommand} = require('@aws-sdk/client-dynamodb');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { sendEmailOTP } = require('../../utils/sendEmailOTP');
const { sendSmsOTP } = require('../../utils/sendSmsOTP');
const User = require('./authModel');

// Signup with OTP
exports.signup = async (req, res) => {
    try {
        const { email, phone,role } = req.body;

     const validRoles=["EndUser","ServiceProvider"];
     if(!role || !validRoles.includes(role)){
        return res.status(400).json({message:"Invalid role selected"});
     }

        if (!email && !phone) return res.status(400).json({ message: 'Email or phone is required' });

        const existingUser = await User.findUserByEmailOrPhone(email, phone);
        if (existingUser) return res.status(400).json({ message: 'User already exists' });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

        await User.createUser({ email, phone,role, otp, otpExpiry });
        console.log(`Generated OTP for ${email || phone}: ${otp}`);

        if (email) await sendEmailOTP(email, otp);
        if (phone) await sendSmsOTP(phone, otp);

        res.status(200).json({ message: 'OTP sent' });
    } catch (error) {
        console.error('Error in signup:', error);
        res.status(500).json({ message: 'Server error',error:error.message });
    }
};

// Verify OTP
exports.verifyOTP = async (req, res) => {
    try {
        const { email, phone, otp } = req.body;

        console.log("Request body:", req.body);

        const user = await User.findUserByEmailOrPhone(email, phone);
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        const storedOtp = user.otp.S;
        const otpExpiry = user.otpExpiry.S;

        console.log(`Stored OTP: ${storedOtp}, Provided OTP: ${otp}`);
        console.log(`OTP Expiry Time: ${otpExpiry} (Database), Current Time: ${new Date().toISOString()} (UTC)`);

        if (storedOtp !== otp) {
            return res.status(400).json({ message: 'Incorrect OTP' });
        }

        if (new Date(otpExpiry) < Date.now()) {
            return res.status(400).json({ message: 'Expired OTP' });
        }

        const token = jwt.sign({ email: user.email.S, phone: user.phone.S }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const updateParams = {
            TableName: process.env.DYNAMODB_TABLE_NAME,
            Key: {
                usersPartitionkey: { S: user.usersPartitionkey.S },
                usersSortKey: { S: 'user' },
            },
            UpdateExpression: 'REMOVE otp, otpExpiry',
        };

        await dynamoDB.send(new UpdateItemCommand(updateParams));

        res.status(200).json({ message: 'OTP verified', token });
    } catch (error) {
        console.error('Error in verifyOTP:', error);
        res.status(500).json({ message: 'Server error',error:error.message });
    }
};

// Create Password
exports.createPassword = async (req, res) => {
    try {
        const { token, password } = req.body;

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const identifier = decoded.email || decoded.phone;

        if (!identifier) {
            return res.status(400).json({ message: 'Invalid token data' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        console.log('Identifier:', identifier);
        console.log('Update Expression:', 'SET password = :password');
        console.log('Expression Attribute Values:', { ':password': { S: hashedPassword } });

        await User.updateUser(identifier, 'SET password = :password', { ':password': { S: hashedPassword } });

        res.status(200).json({ message: 'Password created successfully' });
    } catch (error) {
        console.error('Error in createPassword:', error);
        res.status(500).json({ message: 'Server error' ,error:error.message});
    }
};

// Login
exports.login = async (req, res) => {
    try {
        console.log("login hit");

        const { email, phone, password } = req.body;
        if(!email && !phone){
            return res.status(400).json({message:"Email or phone is required"});
        }
        const user = await User.findUserByEmailOrPhone(email, phone);
        console.log("user",user);
   

        // if (!user || !(await bcrypt.compare(password, user.password.S))) {
        //     return res.status(400).json({ message: 'Invalid credentials'});
        // }
        if (!user ) {
            return res.status(400).json({ message: 'Invalid credentials'});
        }
        if (!user.password || !user.password.S) {
            return res.status(400).json({ message: 'User data corrupted password must match'});
        }
        const isPasswordValid=await bcrypt.compare(password, user.password.S);
        if(!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid password'})
        }
      const role=user.role?.S;
      if(!role){
        return res.status(500).json({ message: 'User role data corrupted'})
      }


      const validRoles=['EndUser', 'ServiceProvider', 'ServiceProviderEmployee', 'Admin'];
      if (!validRoles.includes(role)) {
        console.warn(`Invalid role login attempt: ${role}`);
        return res.status(403).json({ message: 'Unauthorized role' });
    }


        const token = jwt.sign({ email:user.email?.S, phone: user.phone?.S,role}, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful', token,role });
    } catch (error) {
        console.error('Error in login:', error);
        res.status(500).json({ message: 'Server error',error:error.message });
    }
};

exports.forgetPassword=async(req,res)=>{
    try {
        const {email,phone}=req.body;
        const user=await User.findUserByEmailOrPhone(email,phone);
        if(!user) return res.status(400).json({message:"User not found"})
            

     const otp=Math.floor(100000 + Math.random() * 900000).toString();
     const otpExpiry=new Date(Date.now() + 10 *60 *1000);

     await User.updateUser(user.usersPartitionkey.S,'SET otp= :otp,otpExpiry = :otpExpiry',{
        ":otp" : {S:otp},
        ":otpExpiry" : {S:otpExpiry.toISOString()}
     })

     if(email) await sendEmailOTP(email,otp);
     if(phone) await sendSmsOTP(phone,otp);
     console.log(`Generated OTP for ${email || phone}: ${otp}`);

     res.status(200).json({message:"Otp send for password reset"})

    } catch (error) {
         res.status(500).json({message:"Server error, error sending otp",error:error.message})
    }
}

// exports.logout=async(req,res)=>{
//     try {
//         const {email,phone}=req.body;
        
//         const token=req.headers.authorization?.split(' ')[1];
        
//         if(!token) return res.status(400).json({message:"No token provided"});
        
//         const user=await User.findUserByEmailOrPhone(email,phone);
//         if(!user){
//             return res.status(404).json({message:"User not found"});
//         }
//     //Add token to blacklist
//     const params={
//         TableName:process.env.DYNAMODB_TABLE_NAME,
//         Key: {
//             usersPartitionkey: { S: user.usersPartitionkey.S },
//             usersSortKey: { S: 'user' },
//         },
//        UpdateExpression:"REMOVE #token",
//        ExpressionAttributeNames:{
//         '#token':'token'
//        }


//     }

//     await dynamoDB.send(new UpdateItemCommand(params));
//     res.status(200).json({message:"Logout successfull.Token invalidated."})
// } catch (error) {
//         res.status(500).json({message:"Server error",error:error.message})
        
// }

// }


exports.logout=async(req,res)=>{
    try {
        const token=req.headers.authorization?.split(' ')[1];
        console.log("token",token);
        
        if(!token){
            console.warn("Logout attempt without token");
            return res.status(400).json({message:"No token provided",error:error.message})
        }
       

        const decoded=jwt.verify(token,process.env.JWT_SECRET);
        const user=await User.findUserByEmailOrPhone(decoded.email,decoded.phone);
        // try {
            
        //     if(!decoded){
        //        console.log("Invalid token");
        //        return res.status(400).json({message:"Invalid token",error:error.message})
               
        //    }
        // } catch (error) {
        //     console.log("Token invalid,please give correct token");
        //     return res.status(400).json({message:"Invalid token,provide correct token",error:error})
            
        // }

        if(!user){
            console.warn(`Logout attempt for non-existent user: ${decoded.email || decoded.phone}`);
            return res.status(404).json({message: 'User not found'})
        }

         // Validate if the decoded email or phone matches the user in the database
         if ((decoded.email && decoded.email !== user.email.S) || (decoded.phone && decoded.phone !== user.phone.S)) {
            console.warn("Token user mismatch");
            return res.status(403).json({ message: "Invalid token for the user" });
        }

        console.log(`User ${decoded.email || decoded.phone} with role ${decoded.role} logged out`);
         
        const params={
                    TableName:process.env.DYNAMODB_TABLE_NAME,
                    Key: {
                        usersPartitionkey: { S: user.usersPartitionkey.S },
                        usersSortKey: { S: 'user' },
                    },
                   UpdateExpression:"REMOVE #token",
                   ExpressionAttributeNames:{
                    '#token':'token'
                   }
            
            
                }
            
                await dynamoDB.send(new UpdateItemCommand(params));
                res.status(200).json({message:"Logout successfull.Token invalidated."})

    } catch (error) {
        console.log("Failed to logout",error);
        return res.status(500).json({message:"Failed to logout",error:error.message})
        
    }
}




exports.resendOTP = async (req, res) => {
    try {
        const { email, phone } = req.body;
        const user = await User.findUserByEmailOrPhone(email, phone);
        if (!user) return res.status(400).json({ message: 'User not found' });

        //Check if existing OTP is still valid
        // const otpExpiry = new Date(user.otpExpiry);
        // if (otpExpiry > Date.now()) {
        //     console.log(`Resend OTP request for ${email || phone}: Previous OTP still valid until ${otpExpiry}`);
        //     return res.status(400).json({ message: 'Current OTP is still valid. Please check your messages.' });
        // }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const newOtpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        await User.updateUser(user.usersPartitionkey.S, 'SET otp = :otp, otpExpiry = :otpExpiry', {
            ':otp': { S: otp },
            ':otpExpiry': { S: newOtpExpiry.toISOString() },
        });

        if (email) await sendEmailOTP(email, otp);
        if (phone) await sendSmsOTP(phone, otp);
              console.log(`New otp generated and sent to ${email || phone}:${otp}`);
              
        res.status(200).json({ message: 'OTP resent' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
};


exports.createEmployee=async(req,res)=>{
    try {
        const {serviceProviderEmail,serviceProviderPhone,employeeEmail,phone}=req.body;
        const serviceProvider=await User.findUserByEmailOrPhone(serviceProviderEmail,serviceProviderPhone);
        if(!serviceProvider || serviceProvider.role?.S!== "ServiceProvider"){
            return res.status(403).json({message: 'Only service providers can create their employee account'})
        }

        const existingEmployee=await User.findUserByEmailOrPhone(employeeEmail,phone);

        if(existingEmployee) return res.status(400).json({message: 'Employee already exists'});

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

    //   const hashedPassword=await bcrypt.hash(password,10);
          

      if (employeeEmail) await sendEmailOTP(employeeEmail, otp);
      if (phone) await sendSmsOTP(phone, otp);
      console.log(`Generated OTP for ${employeeEmail || phone}: ${otp}`);

      res.status(200).json({ message: 'OTP sent' });
     await User.createUser({
        email:employeeEmail,
        phone,
        role:"ServiceProviderEmployee",
        // password:hashedPassword,
        otp,
        otpExpiry,
    
      })


    //   return res.status(201).json({message:"Employee account created successfully",employee})
    } catch (error) {
        return res.status(500).json({message:"Server error",error:error.message})
    }
}
