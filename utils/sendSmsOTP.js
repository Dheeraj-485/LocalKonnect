require("dotenv").config()
const { sns } = require('../config/awsConfig');
const { PublishCommand } = require('@aws-sdk/client-sns');

exports.sendSmsOTP = async (phone, otp) => {
    const params = {
        Message: `Your OTP is ${otp}`,
        PhoneNumber: phone,
    };
    
    const command = new PublishCommand(params);
    await sns.send(command);
};
