require("dotenv").config()
const { ses } = require('../config/awsConfig');
const { SendEmailCommand } = require('@aws-sdk/client-ses');

exports.sendEmailOTP = async (email, otp) => {
    const params = {
        Destination: {
            ToAddresses: [email]
        },
        Message: {
            Body: {
                Text: {
                    Data: `Your OTP is ${otp}`
                }
            },
            Subject: {
                Data: 'Your OTP for verification'
            }
        },
        Source: process.env.SES_EMAIL_FROM,
    };
    
    const command = new SendEmailCommand(params);
    await ses.send(command);
};
