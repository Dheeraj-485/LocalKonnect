require("dotenv").config() 
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { SESClient } = require('@aws-sdk/client-ses');
const { SNSClient } = require('@aws-sdk/client-sns');
         

const dynamoDB = new DynamoDBClient({ region: process.env.AWS_REGION });
const ses = new SESClient({ region: process.env.AWS_REGION });
const sns = new SNSClient({ region: process.env.AWS_REGION });

module.exports = { dynamoDB, ses, sns };
